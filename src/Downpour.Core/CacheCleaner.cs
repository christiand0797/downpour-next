namespace Downpour.Core;

/// <summary>One group of Downpour's own files the person may clear from Settings.</summary>
public sealed record CacheCategory(string Id, string Title, string Explanation, bool SelectedByDefault, bool NeedsWarning);

public sealed record CacheUsage(CacheCategory Category, int Files, long Bytes);

public sealed record CacheCleanResult(int FilesDeleted, long BytesFreed, int FilesInUse, int FilesFailed);

/// <summary>
/// Measures and clears Downpour's own caches under %LOCALAPPDATA%\DownpourNext. Every category is a fixed folder and file
/// pattern; nothing outside the data folder is touched, reparse points (junctions, symbolic links) are never followed or
/// deleted, and files another Downpour process holds open are skipped. The tamper-evident action log, quarantine vault,
/// alert history, operation journal, preferences and parental settings are never in any category.
/// </summary>
public static class CacheCleaner
{
    public const string TemporaryFiles = "temp";
    public const string ThreatDatabases = "threat-db";
    public const string VulnerabilityCatalog = "threat-intel";
    public const string Logs = "logs";
    public const string UpdateLeftovers = "updates";
    public const string EmergencySnapshots = "snapshots";
    public const string Baselines = "baselines";

    public static readonly IReadOnlyList<CacheCategory> Categories =
    [
        new(TemporaryFiles, "Leftover temporary files", "Partial downloads and temporary files left by an interrupted update or crash. Always safe to remove.", true, false),
        new(UpdateLeftovers, "Downloaded app updates", "Update packages and the update helper copy kept after an update finished.", true, false),
        new(Logs, "Logs", "Troubleshooting logs from the sensor service and crash reports. The log in use is kept.", true, false),
        new(VulnerabilityCatalog, "Vulnerability catalog and lookups", "The cached CISA exploited-vulnerability catalog and saved lookup results. Downloaded again when needed.", false, false),
        new(ThreatDatabases, "Downloaded threat databases", "The 45 public threat databases. Downpour downloads them again on its next update (about 100 MB); until then, matching uses what is already loaded.", false, false),
        new(EmergencySnapshots, "Emergency snapshots", "Process and connection snapshots saved by Emergency mode. These can be evidence; export anything you need first.", false, true),
        new(Baselines, "Learned baselines", "What Downpour learned is normal for this PC (DNS names, startup items, audio devices). Clearing makes it relearn, and anything already on the PC is then treated as normal.", false, true),
    ];

    /// <summary>Files that must never be deleted by the cleaner, whatever the pattern.</summary>
    private static readonly HashSet<string> Protected = new(StringComparer.OrdinalIgnoreCase)
    {
        "action-audit.v1.jsonl", "action-audit.v1.jsonl.anchor", "action-audit.v1.jsonl.key", "audit-verification.v1.json",
        "alerts.v1.db", "operations.v1.db", "vault.key", "preferences.v1.ini", "parental_config.json",
    };

    public static string DefaultRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext");

    public static IReadOnlyList<CacheUsage> Measure(string root) =>
        Categories.Select(category =>
        {
            var files = FilesFor(root, category.Id).ToArray();
            return new CacheUsage(category, files.Length, files.Sum(f => SafeLength(f)));
        }).ToArray();

    public static CacheCleanResult Clean(string root, IEnumerable<string> categoryIds, string? keepFile = null)
    {
        int deleted = 0, inUse = 0, failed = 0;
        long freed = 0;
        foreach (var id in categoryIds.Distinct(StringComparer.Ordinal))
        {
            if (Categories.All(c => c.Id != id)) continue;
            foreach (var file in FilesFor(root, id).ToArray())
            {
                if (keepFile is not null && string.Equals(Path.GetFullPath(file.FullName), Path.GetFullPath(keepFile), StringComparison.OrdinalIgnoreCase)) continue;
                var length = SafeLength(file);
                try
                {
                    file.Refresh();
                    if (!file.Exists) continue;
                    if (file.Attributes.HasFlag(FileAttributes.ReadOnly)) file.Attributes &= ~FileAttributes.ReadOnly;
                    file.Delete();
                    deleted++;
                    freed += length;
                }
                catch (IOException) { inUse++; }
                catch (UnauthorizedAccessException) { failed++; }
            }
        }
        RemoveEmptyFolders(Path.Combine(root, "updates"));
        RemoveEmptyFolders(Path.Combine(root, "update-helper"));
        return new CacheCleanResult(deleted, freed, inUse, failed);
    }

    private static IEnumerable<FileInfo> FilesFor(string root, string categoryId)
    {
        var full = Path.GetFullPath(root);
        if (!Directory.Exists(full) || IsReparse(full)) return [];
        return categoryId switch
        {
            // Anywhere in the data folder except the quarantine vault, whose files must stay with their records.
            TemporaryFiles => Walk(full, recursive: true).Where(f => f.Name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
                && !Under(f.FullName, Path.Combine(full, "state", "quarantine"))),
            ThreatDatabases => Walk(Path.Combine(full, "threat-db"), recursive: false).Where(f => f.Name.EndsWith(".cache", StringComparison.OrdinalIgnoreCase)),
            VulnerabilityCatalog => Walk(Path.Combine(full, "threat-intel"), recursive: false)
                .Concat(Walk(Path.Combine(full, "state"), recursive: false).Where(f => f.Name.Equals("intel-results.v1.json", StringComparison.OrdinalIgnoreCase))),
            Logs => Walk(Path.Combine(full, "logs"), recursive: false).Where(f => f.Extension is ".log" or ".txt"),
            UpdateLeftovers => Walk(Path.Combine(full, "updates"), recursive: true).Concat(Walk(Path.Combine(full, "update-helper"), recursive: true)),
            EmergencySnapshots => Walk(Path.Combine(full, "emergency_snapshots"), recursive: false).Where(f => f.Extension.Equals(".json", StringComparison.OrdinalIgnoreCase)),
            Baselines => Walk(Path.Combine(full, "state"), recursive: false).Where(f => f.Name is "dns-baseline.v1.json" or "persistence-baseline.v1.json" or "audio-devices.v1.json"),
            _ => [],
        };
    }

    private static IEnumerable<FileInfo> Walk(string directory, bool recursive)
    {
        if (!Directory.Exists(directory) || IsReparse(directory)) yield break;
        var pending = new Stack<string>([directory]);
        var visited = 0;
        while (pending.Count > 0 && visited++ < 4096)
        {
            var current = pending.Pop();
            FileInfo[] files;
            DirectoryInfo[] children;
            try
            {
                var info = new DirectoryInfo(current);
                files = info.GetFiles();
                children = recursive ? info.GetDirectories() : [];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            foreach (var file in files)
                if (!file.Attributes.HasFlag(FileAttributes.ReparsePoint) && !Protected.Contains(file.Name)) yield return file;
            foreach (var child in children)
                if (!child.Attributes.HasFlag(FileAttributes.ReparsePoint)) pending.Push(child.FullName);
        }
    }

    private static void RemoveEmptyFolders(string directory)
    {
        try
        {
            if (!Directory.Exists(directory) || IsReparse(directory)) return;
            foreach (var child in Directory.GetDirectories(directory))
                if (!IsReparse(child)) RemoveEmptyFolders(child);
            if (Directory.GetFileSystemEntries(directory).Length == 0) Directory.Delete(directory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static bool IsReparse(string path)
    {
        try { return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return true; }
    }

    private static bool Under(string path, string folder) =>
        path.StartsWith(Path.TrimEndingDirectorySeparator(folder) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static long SafeLength(FileInfo file)
    {
        try { return file.Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }
    }
}
