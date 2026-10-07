using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Read-only, bounded comparison of this installation with its unsigned local release manifest.</summary>
public static class PackageIntegrityInspector
{
    public const int MaximumManifestBytes = 1024 * 1024;
    public const int MaximumFiles = 2000;
    public const long MaximumExpandedBytes = 1024L * 1024 * 1024;
    public const long MaximumFileBytes = 256L * 1024 * 1024;
    public const string Scope = "Listed package files only; extra files and user state are excluded. The local manifest is unsigned and replaceable by the same user. Matching hashes show consistency, not publisher authenticity or absence of malware. This is an explicit point-in-time check, not continuous protection.";

    public static async Task<PackageIntegrityAssessment> InspectAsync(string installRoot, string expectedVersion,
        IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var token = deadline.Token;
        var findings = new List<PackageIntegrityFinding>();
        string? version = null, source = null, manifestHash = null;
        int expected = 0, checkedFiles = 0, matching = 0;
        long bytes = 0;
        PackageIntegrityAssessment Result(string status) => new(1, DateTimeOffset.UtcNow, status, version, source,
            manifestHash, expected, checkedFiles, matching, bytes, findings.ToArray(), Scope);
        try
        {
            token.ThrowIfCancellationRequested();
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(installRoot));
            RejectLinks(root, "release-manifest.json");
            var manifestPath = Path.Combine(root, "release-manifest.json");
            byte[] raw;
            await using (var stream = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true))
            {
                if (stream.Length is < 1 or > MaximumManifestBytes) throw new InvalidDataException();
                raw = new byte[stream.Length];
                await stream.ReadExactlyAsync(raw, token).ConfigureAwait(false);
                if (await stream.ReadAsync(new byte[1], token).ConfigureAwait(false) != 0) throw new InvalidDataException();
            }
            RejectLinks(root, "release-manifest.json");
            manifestHash = Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant();
            var manifest = Parse(raw, expectedVersion);
            version = manifest.Version;
            source = manifest.SourceCommit;
            expected = manifest.Files.Count;
            foreach (var file in manifest.Files)
            {
                token.ThrowIfCancellationRequested();
                progress?.Report($"Checking {checkedFiles + 1}/{expected}: {file.Path}");
                try
                {
                    RejectLinks(root, file.Path);
                    var path = Path.Combine(root, file.Path.Replace('/', Path.DirectorySeparatorChar));
                    await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
                    if (stream.Length != file.Bytes)
                    {
                        findings.Add(new(file.Path, "Size mismatch"));
                        checkedFiles++;
                        continue;
                    }
                    var digest = await SHA256.HashDataAsync(stream, token).ConfigureAwait(false);
                    bytes += stream.Length;
                    RejectLinks(root, file.Path);
                    if (Convert.ToHexString(digest).Equals(file.Sha256, StringComparison.OrdinalIgnoreCase)) matching++;
                    else findings.Add(new(file.Path, "SHA-256 mismatch"));
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                { findings.Add(new(file.Path, "Missing")); }
                catch (InvalidDataException) { findings.Add(new(file.Path, "Unsafe path or link")); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { findings.Add(new(file.Path, "Unreadable")); }
                checkedFiles++;
            }
            return Result(findings.Count == 0 ? "Matches local manifest" : "Differences or unavailable files");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { findings.Add(new("", "Check exceeded its 30-second budget")); return Result("Incomplete"); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        { findings.Add(new("release-manifest.json", "Manifest absent; use a complete released portable package")); return Result("Unavailable"); }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or ArgumentException or OverflowException or FormatException)
        { findings.Add(new("release-manifest.json", "Manifest or path failed validation")); return Result("Invalid manifest"); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { findings.Add(new("release-manifest.json", "Manifest cannot be read")); return Result("Unavailable"); }
    }

    private static Manifest Parse(byte[] raw, string expectedVersion)
    {
        // Strict UTF-8, duplicate rejection and exact fields prevent ambiguous baselines.
        using var text = new StringReader(new UTF8Encoding(false, true).GetString(raw).TrimStart('\uFEFF'));
        using var reader = new JsonTextReader(text) { MaxDepth = 8, DateParseHandling = DateParseHandling.None };
        var obj = JObject.Load(reader, new JsonLoadSettings { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error });
        while (reader.Read()) throw new InvalidDataException();
        ExactFields(obj, "schemaVersion", "version", "sourceCommit", "files");
        if (obj["schemaVersion"]?.Type != JTokenType.Integer || obj.Value<long>("schemaVersion") != 1 ||
            obj["version"]?.Type != JTokenType.String || obj.Value<string>("version") != expectedVersion ||
            expectedVersion.Length > 32 || !Version.TryParse(expectedVersion, out var parsed) || parsed.Build < 0 || parsed.Revision >= 0 ||
            obj["sourceCommit"]?.Type != JTokenType.String || !Hex(obj.Value<string>("sourceCommit"), 40) ||
            obj["files"] is not JArray files || files.Count is < 2 or > MaximumFiles)
            throw new InvalidDataException();
        var entries = new List<Entry>();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        foreach (var item in files)
        {
            if (item is not JObject file) throw new InvalidDataException();
            ExactFields(file, "path", "bytes", "sha256");
            if (file["path"]?.Type != JTokenType.String || file["bytes"]?.Type != JTokenType.Integer ||
                file["sha256"]?.Type != JTokenType.String) throw new InvalidDataException();
            var path = file.Value<string>("path")!;
            var size = file.Value<long>("bytes");
            var sha = file.Value<string>("sha256")!;
            if (!SafePath(path) || !paths.Add(path) || size is < 0 or > MaximumFileBytes || !Hex(sha, 64) ||
                total + size > MaximumExpandedBytes) throw new InvalidDataException();
            total += size;
            entries.Add(new(path, size, sha));
        }
        if (!paths.Contains("Downpour.Desktop.exe") || !paths.Contains("service/Downpour.Service.exe")) throw new InvalidDataException();
        return new(expectedVersion, obj.Value<string>("sourceCommit")!, entries);
    }

    private static void ExactFields(JObject obj, params string[] names)
    {
        if (obj.Properties().Count() != names.Length || obj.Properties().Any(p => !names.Contains(p.Name, StringComparer.Ordinal)))
            throw new InvalidDataException();
    }

    private static bool Hex(string? value, int length) => value?.Length == length && value.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool SafePath(string path)
    {
        if (path.Length is < 1 or > 512 || path.Any(char.IsControl) || path.Contains('\\') || path.Contains(':') || path.StartsWith('/')) return false;
        foreach (var segment in path.Split('/'))
        {
            if (segment.Length == 0 || segment is "." or ".." || segment != segment.Trim() || segment.EndsWith('.') ||
                segment.IndexOfAny(['<', '>', '"', '|', '?', '*']) >= 0 ||
                segment.Equals(".downpour-update", StringComparison.OrdinalIgnoreCase) ||
                segment.Equals("release-manifest.json", StringComparison.OrdinalIgnoreCase)) return false;
            var stem = segment.Split('.')[0].ToUpperInvariant();
            if (stem is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
                (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9')) return false;
        }
        return true;
    }

    private static void RejectLinks(string root, string relative)
    {
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
        var current = root;
        foreach (var segment in relative.Split('/'))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
        }
    }
    private sealed record Entry(string Path, long Bytes, string Sha256);
    private sealed record Manifest(string Version, string SourceCommit, IReadOnlyList<Entry> Files);
}
