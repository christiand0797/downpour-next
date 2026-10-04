using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Downpour.Core;

/// <summary>Bounded, atomic cache for the validated CISA KEV source payload.</summary>
public sealed class KevCatalogCache
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("DPKEV001");
    private const int HeaderLength = 8 + sizeof(long) + sizeof(int) + 32;
    public static readonly TimeSpan MaximumAge = TimeSpan.FromDays(7);
    private static readonly TimeSpan MaximumFutureSkew = TimeSpan.FromMinutes(5);

    public KevCatalogCache(string? path = null) => CachePath = path ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DownpourNext", "threat-intel", "cisa-kev.v1.cache");

    public string CachePath { get; }

    /// <summary>Returns null when no cache exists or its validated source data has expired.</summary>
    public KevCachedCatalog? TryRead(DateTimeOffset? nowUtc = null)
    {
        if (!File.Exists(CachePath)) return null;
        var info = new FileInfo(CachePath);
        if (info.Length < HeaderLength || info.Length > KevCatalogClient.MaximumPayloadBytes + HeaderLength)
            throw new InvalidDataException("The KEV cache file size is invalid.");

        var bytes = File.ReadAllBytes(CachePath);
        if (bytes.Length < HeaderLength || !bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("The KEV cache header is invalid.");

        var retrievedUnixSeconds = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(8, sizeof(long)));
        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, sizeof(int)));
        if (payloadLength <= 0 || payloadLength > KevCatalogClient.MaximumPayloadBytes || bytes.Length != HeaderLength + payloadLength)
            throw new InvalidDataException("The KEV cache payload length is invalid.");

        DateTimeOffset retrievedAtUtc;
        try { retrievedAtUtc = DateTimeOffset.FromUnixTimeSeconds(retrievedUnixSeconds); }
        catch (ArgumentOutOfRangeException exception) { throw new InvalidDataException("The KEV cache timestamp is invalid.", exception); }

        var now = nowUtc ?? DateTimeOffset.UtcNow;
        var age = now - retrievedAtUtc;
        if (age < -MaximumFutureSkew) throw new InvalidDataException("The KEV cache timestamp is in the future.");
        if (age > MaximumAge) return null;

        var payload = bytes.AsSpan(HeaderLength, payloadLength);
        var expectedDigest = bytes.AsSpan(20, 32);
        Span<byte> actualDigest = stackalloc byte[32];
        SHA256.HashData(payload, actualDigest);
        if (!CryptographicOperations.FixedTimeEquals(actualDigest, expectedDigest))
            throw new InvalidDataException("The KEV cache integrity check failed.");

        var snapshot = KevCatalogClient.Parse(payload.ToArray()) with { RetrievedAtUtc = retrievedAtUtc };
        return new KevCachedCatalog(snapshot, age > TimeSpan.FromHours(24), age < TimeSpan.Zero ? TimeSpan.Zero : age);
    }

    /// <summary>Stores only a network payload that has already passed the live source validator.</summary>
    public void Write(KevCatalogDownload download)
    {
        ArgumentNullException.ThrowIfNull(download);
        if (download.Payload.Length is 0 or > KevCatalogClient.MaximumPayloadBytes)
            throw new InvalidDataException("The KEV cache payload is empty or exceeds its size limit.");

        // Validate again at the persistence boundary so this class cannot be used to cache unchecked data.
        _ = KevCatalogClient.Parse(download.Payload);
        var directory = Path.GetDirectoryName(CachePath) ?? throw new InvalidDataException("The KEV cache path has no parent directory.");
        Directory.CreateDirectory(directory);

        var tempPath = CachePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                Span<byte> header = stackalloc byte[HeaderLength];
                Magic.CopyTo(header);
                BinaryPrimitives.WriteInt64LittleEndian(header[8..], download.Snapshot.RetrievedAtUtc.ToUnixTimeSeconds());
                BinaryPrimitives.WriteInt32LittleEndian(header[16..], download.Payload.Length);
                SHA256.HashData(download.Payload, header[20..52]);
                stream.Write(header);
                stream.Write(download.Payload);
                stream.Flush(flushToDisk: true);
            }
            File.Move(tempPath, CachePath, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}

public sealed record KevCachedCatalog(KevCatalogSnapshot Snapshot, bool IsStale, TimeSpan Age);
