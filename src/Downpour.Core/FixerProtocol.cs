using System.Text.Json;

namespace Downpour.Core;

/// <summary>Progress of a long fixer job (Windows Update), written by the fixer and polled by the desktop.</summary>
public sealed record FixerStatus(string Stage, int Percent, string Message, bool Finished, DateTimeOffset UpdatedUtc);

/// <summary>
/// How the desktop and the elevated Downpour.Fixer talk: fixed verbs and arguments on the command line, and JSON
/// written by the fixer into %ProgramData%\DownpourNext\fixer, which only administrators and SYSTEM can write.
/// The desktop only reads from there, so another program running as the user cannot forge a result or a backup.
/// </summary>
public static class FixerProtocol
{
    public const string Apply = "apply";
    public const string Undo = "undo";
    public const string Updates = "updates";
    public static readonly IReadOnlySet<string> UpdateScopes = new HashSet<string>(StringComparer.Ordinal) { "software", "drivers", "all" };
    public const int MaximumJsonBytes = 512 * 1024;

    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DownpourNext", "fixer");
    public static string ResultPath(string requestId) => Path.Combine(Root, "results", requestId + ".json");
    public static string StatusPath(string requestId) => Path.Combine(Root, "status", requestId + ".json");
    public static string BackupPath(string backupId) => Path.Combine(Root, "backups", backupId + ".json");
    public static string AuditPath => Path.Combine(Root, "fix-audit.jsonl");

    public static bool IsId(string? value) => value is { Length: 32 } && Guid.TryParseExact(value, "N", out _);

    /// <summary>Validates a full command line; anything else is refused before any change.</summary>
    public static bool IsValidCommand(IReadOnlyList<string> args, out string error)
    {
        error = "";
        if (args.Count != 3 || !IsId(args[1])) { error = "Expected: <verb> <request id> <argument>."; return false; }
        switch (args[0])
        {
            case Apply:
                var ids = args[2].Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (ids.Length is 0 or > 64 || !ids.All(HardeningFixes.IsValidId)) { error = "Unknown fix requested."; return false; }
                return true;
            case Undo:
                if (!IsId(args[2])) { error = "Invalid backup id."; return false; }
                return true;
            case Updates:
                if (!UpdateScopes.Contains(args[2])) { error = "Invalid update scope."; return false; }
                return true;
            default:
                error = "Unknown verb.";
                return false;
        }
    }

    public static T? ReadJson<T>(string path) where T : class
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaximumJsonBytes || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) return null;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize<T>(stream, HardeningFixes.Json);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException) { return null; }
    }

    /// <summary>Most recent backups first (for Undo).</summary>
    public static IReadOnlyList<FixBackup> RecentBackups(int max = 20)
    {
        try
        {
            var folder = new DirectoryInfo(Path.Combine(Root, "backups"));
            if (!folder.Exists) return [];
            return folder.GetFiles("*.json").OrderByDescending(f => f.LastWriteTimeUtc).Take(max)
                .Select(f => ReadJson<FixBackup>(f.FullName)).OfType<FixBackup>().Where(b => IsId(b.BackupId) && b.Entries.Count > 0).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }
}
