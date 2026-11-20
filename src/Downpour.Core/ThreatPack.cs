using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Downpour.Core;

public sealed record ThreatPackEntry(string Name, long Bytes, string Sha256);

public sealed record ThreatPackManifest(int SchemaVersion, string CreatedBy, DateTimeOffset CreatedAtUtc, IReadOnlyList<ThreatPackEntry> Files);

/// <summary>
/// A portable bundle of already-validated feed payloads and/or rules for machines that cannot download them
/// (air-gapped or intentionally offline). The format is a ZIP with a hashed manifest; reading rejects traversal,
/// duplicate names, unexpected entries, size overruns and any hash mismatch. It carries no executable content and
/// does not imply trust beyond "these bytes are the bytes the pack describes".
/// </summary>
public static class ThreatPack
{
    public const int SchemaVersion = 1;
    public const int MaximumFiles = 256;
    public const long MaximumFileBytes = 64L * 1024 * 1024;
    public const long MaximumTotalBytes = 128L * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static void Write(Stream destination, string createdBy, IEnumerable<(string Name, byte[] Content)> files)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentException.ThrowIfNullOrWhiteSpace(createdBy);
        var entries = files.Select(file => (Name: SafeName(file.Name), file.Content)).ToArray();
        if (entries.Length is 0 or > MaximumFiles) throw new InvalidDataException("The pack has an invalid file count.");
        if (entries.Select(entry => entry.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != entries.Length)
            throw new InvalidDataException("The pack contains duplicate names.");
        if (entries.Sum(entry => (long)entry.Content.Length) > MaximumTotalBytes)
            throw new InvalidDataException("The pack exceeds its total size limit.");
        foreach (var (name, content) in entries)
        {
            if (content.Length is 0 || content.Length > MaximumFileBytes)
                throw new InvalidDataException($"The pack entry {name} has an invalid size.");
        }
        var manifest = new ThreatPackManifest(SchemaVersion, createdBy.Trim()[..Math.Min(createdBy.Trim().Length, 64)],
            DateTimeOffset.UtcNow, entries.Select(entry => new ThreatPackEntry(entry.Name, entry.Content.Length,
                Convert.ToHexString(SHA256.HashData(entry.Content)).ToLowerInvariant())).ToArray());
        using var archive = new ZipArchive(destination, ZipArchiveMode.Create, leaveOpen: true);
        var manifestEntry = archive.CreateEntry("pack.json", CompressionLevel.Optimal);
        using (var stream = manifestEntry.Open()) JsonSerializer.Serialize(stream, manifest, Json);
        foreach (var (name, content) in entries)
        {
            var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
            using var stream = entry.Open();
            stream.Write(content);
        }
    }

    public static (ThreatPackManifest Manifest, IReadOnlyList<(string Name, byte[] Content)> Files) Read(Stream source)
    {
        ArgumentNullException.ThrowIfNull(source);
        using var archive = new ZipArchive(source, ZipArchiveMode.Read, leaveOpen: true);
        if (archive.Entries.Count is < 2 or > MaximumFiles + 1) throw new InvalidDataException("The pack has an invalid entry count.");
        var manifestEntry = archive.Entries.FirstOrDefault(entry => entry.FullName == "pack.json")
            ?? throw new InvalidDataException("The pack manifest is missing.");
        ThreatPackManifest manifest;
        using (var stream = manifestEntry.Open()) manifest = JsonSerializer.Deserialize<ThreatPackManifest>(stream, Json)
            ?? throw new InvalidDataException("The pack manifest is invalid.");
        if (manifest.SchemaVersion != SchemaVersion) throw new InvalidDataException($"Unsupported pack schema {manifest.SchemaVersion}.");
        if (manifest.Files is null || manifest.Files.Count is 0 or > MaximumFiles) throw new InvalidDataException("The pack manifest has an invalid file count.");
        var expected = manifest.Files.ToDictionary(file => file.Name, StringComparer.Ordinal);
        if (expected.Count != manifest.Files.Count) throw new InvalidDataException("The pack manifest contains duplicate names.");
        var contents = new List<(string Name, byte[] Content)>(expected.Count);
        long total = 0;
        foreach (var entry in archive.Entries)
        {
            if (entry.FullName == "pack.json") continue;
            if (!expected.TryGetValue(entry.FullName, out var declared)) throw new InvalidDataException($"The pack contains an undeclared entry {entry.FullName}.");
            if (entry.Length is <= 0 or > MaximumFileBytes) throw new InvalidDataException($"The pack entry {entry.FullName} has an invalid size.");
            total += entry.Length;
            if (total > MaximumTotalBytes) throw new InvalidDataException("The pack exceeds its total size limit.");
            using var stream = entry.Open();
            using var buffer = new MemoryStream((int)entry.Length);
            stream.CopyTo(buffer);
            var content = buffer.ToArray();
            if (content.LongLength != declared.Bytes) throw new InvalidDataException($"The pack entry {entry.FullName} has the wrong length.");
            var digest = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            if (!string.Equals(digest, declared.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"The pack entry {entry.FullName} failed its hash check.");
            contents.Add((entry.FullName, content));
        }
        if (contents.Count != expected.Count) throw new InvalidDataException("The pack is missing declared entries.");
        return (manifest, contents);
    }

    private static string SafeName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128 || Path.IsPathRooted(name) || name.Contains(':') ||
            name.Split('/', '\\').Contains("..")) throw new InvalidDataException("The pack entry name is unsafe.");
        return name.Replace('\\', '/');
    }
}
