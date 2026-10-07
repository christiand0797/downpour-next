using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Downpour.Service;

/// <summary>Everything needed to verify and restore a quarantined file. Stored next to the encrypted copy.</summary>
public sealed record QuarantineManifest(
    int SchemaVersion,
    string ObjectId,
    Guid OperationId,
    string OriginalPath,
    long Size,
    string Sha256,
    int Attributes,
    DateTime CreationTimeUtc,
    DateTime LastWriteTimeUtc,
    string? Sddl,
    string? ZoneIdentifier,
    string Reason,
    DateTimeOffset QuarantinedAtUtc,
    DateTimeOffset? RestoredAtUtc = null,
    string? RestoredTo = null);

/// <summary>
/// Encrypted quarantine store in the protected state folder (v29 quarantine_core.py design): AES-256-GCM in 64 KiB
/// chunks with a random per-file nonce prefix and chunk counter, authenticated with the object ID, chunk index, and a
/// final-chunk flag so truncation, reordering, and swapping files are detected. The key is random and DPAPI-protected.
/// </summary>
public sealed class QuarantineVault
{
    public const int ChunkSize = 64 * 1024;
    private static readonly byte[] Magic = "DPQ1"u8.ToArray();
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = false };
    private readonly string _root;
    private readonly Lazy<byte[]> _key;

    public QuarantineVault(string root)
    {
        _root = root;
        Directory.CreateDirectory(root);
        _key = new Lazy<byte[]>(LoadOrCreateKey);
    }

    public static QuarantineVault CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state", "quarantine");
        SecureJournalDirectory.Ensure(root);
        return new QuarantineVault(root);
    }

    public string Root => _root;
    public string ContentPath(string objectId) => Path.Combine(_root, objectId + ".dpq");
    public string ManifestPath(string objectId) => Path.Combine(_root, objectId + ".json");

    public IReadOnlyList<QuarantineManifest> List()
    {
        var results = new List<QuarantineManifest>();
        foreach (var path in Directory.EnumerateFiles(_root, "obj-*.json").Take(10_000))
            if (TryReadManifest(Path.GetFileNameWithoutExtension(path), out var manifest)) results.Add(manifest!);
        return results.OrderByDescending(manifest => manifest.QuarantinedAtUtc).ToArray();
    }

    public bool TryReadManifest(string objectId, out QuarantineManifest? manifest)
    {
        manifest = null;
        try
        {
            var path = ManifestPath(objectId);
            if (!File.Exists(path) || new FileInfo(path).Length > 64 * 1024) return false;
            manifest = JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllBytes(path), Json);
            return manifest is { SchemaVersion: 1 } && manifest.ObjectId == objectId;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    public void WriteManifest(QuarantineManifest manifest)
    {
        var path = ManifestPath(manifest.ObjectId);
        var temporary = path + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, manifest, Json);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>Encrypts <paramref name="read"/> (offset, buffer) => bytes read into the vault; returns the plaintext SHA-256.</summary>
    public string Encrypt(string objectId, long length, Func<long, Span<byte>, int> read)
    {
        var path = ContentPath(objectId);
        var temporary = path + ".tmp";
        var prefix = RandomNumberGenerator.GetBytes(8);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var aes = new AesGcm(_key.Value, 16))
        {
            output.Write(Magic);
            output.Write(prefix);
            var plain = new byte[ChunkSize];
            var cipher = new byte[ChunkSize];
            var tag = new byte[16];
            var header = new byte[5];
            long offset = 0;
            uint index = 0;
            do
            {
                var count = (int)Math.Min(ChunkSize, length - offset);
                var filled = 0;
                while (filled < count)
                {
                    var got = read(offset + filled, plain.AsSpan(filled, count - filled));
                    if (got <= 0) throw new IOException("The file changed size while it was being quarantined.");
                    filled += got;
                }
                sha.AppendData(plain, 0, count);
                offset += count;
                var final = offset >= length;
                aes.Encrypt(Nonce(prefix, index), plain.AsSpan(0, count), cipher.AsSpan(0, count), tag, Aad(objectId, index, final));
                BitConverter.TryWriteBytes(header.AsSpan(0, 4), count);
                header[4] = final ? (byte)1 : (byte)0;
                output.Write(header);
                output.Write(cipher, 0, count);
                output.Write(tag);
                index++;
                if (final) break;
            }
            while (true);
            output.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: false);
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>Decrypts and authenticates every chunk, writing plaintext to <paramref name="output"/> (or nowhere); returns the SHA-256.</summary>
    public string Decrypt(string objectId, Stream? output)
    {
        using var input = new FileStream(ContentPath(objectId), FileMode.Open, FileAccess.Read, FileShare.Read);
        Span<byte> magic = stackalloc byte[4];
        var prefix = new byte[8];
        if (input.Read(magic) != 4 || !magic.SequenceEqual(Magic) || input.Read(prefix) != 8)
            throw new CryptographicException("The quarantine file header is invalid.");
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var aes = new AesGcm(_key.Value, 16);
        var cipher = new byte[ChunkSize];
        var plain = new byte[ChunkSize];
        var tag = new byte[16];
        var header = new byte[5];
        uint index = 0;
        while (true)
        {
            if (input.ReadAtLeast(header, 5, throwOnEndOfStream: false) != 5) throw new CryptographicException("The quarantine file is truncated.");
            var count = BitConverter.ToInt32(header, 0);
            var final = header[4] == 1;
            if (count is < 0 or > ChunkSize || input.ReadAtLeast(cipher.AsSpan(0, count), count, throwOnEndOfStream: false) != count
                || input.ReadAtLeast(tag, 16, throwOnEndOfStream: false) != 16)
                throw new CryptographicException("The quarantine file is truncated.");
            aes.Decrypt(Nonce(prefix, index), cipher.AsSpan(0, count), tag, plain.AsSpan(0, count), Aad(objectId, index, final));
            sha.AppendData(plain, 0, count);
            output?.Write(plain, 0, count);
            index++;
            if (final)
            {
                if (input.Position != input.Length) throw new CryptographicException("The quarantine file has trailing data.");
                break;
            }
        }
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    public void DeleteStaged(string objectId)
    {
        foreach (var path in new[] { ContentPath(objectId), ContentPath(objectId) + ".tmp", ManifestPath(objectId), ManifestPath(objectId) + ".tmp" })
            if (File.Exists(path)) File.Delete(path);
    }

    private static byte[] Nonce(byte[] prefix, uint index)
    {
        var nonce = new byte[12];
        prefix.CopyTo(nonce, 0);
        BitConverter.TryWriteBytes(nonce.AsSpan(8), index);
        return nonce;
    }

    private static byte[] Aad(string objectId, uint index, bool final) => Encoding.UTF8.GetBytes($"{objectId}|{index}|{(final ? 1 : 0)}");

    private byte[] LoadOrCreateKey()
    {
        var path = Path.Combine(_root, "vault.key");
        if (File.Exists(path)) return IntelKeyStore.Unprotect(File.ReadAllBytes(path));
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, IntelKeyStore.Protect(key));
        return key;
    }
}
