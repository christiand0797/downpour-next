using System.Text;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Writes the weekly summary into the per-user reports folder. The file is capped, atomically replaced and readable only
/// by the current user; it contains stored counts and rule titles, never host paths, addresses or file contents.
/// </summary>
public sealed class WeeklyDigestWriter(string reportsRoot)
{
    public const int MaximumReportBytes = 32 * 1024;

    public string ReportsRoot { get; } = Path.GetFullPath(reportsRoot);

    public static WeeklyDigestWriter CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "reports");
        SecureJournalDirectory.Ensure(root);
        return new WeeklyDigestWriter(root);
    }

    public string PathFor(DateTimeOffset nowUtc) => Path.Combine(ReportsRoot, WeeklyDigestCalendar.FileName(nowUtc));

    public bool ExistsFor(DateTimeOffset nowUtc) => File.Exists(PathFor(nowUtc));

    /// <summary>Replaces this week's report atomically and returns its path. An oversized summary is refused, not truncated.</summary>
    public string Write(DateTimeOffset nowUtc, string markdown)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(markdown);
        var bytes = Encoding.UTF8.GetBytes(markdown);
        if (bytes.Length > MaximumReportBytes)
            throw new InvalidOperationException("The weekly summary exceeds its size limit.");
        Directory.CreateDirectory(ReportsRoot);
        var path = PathFor(nowUtc);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);
            SecureJournalDirectory.RestrictExistingFile(temporary);
            File.Move(temporary, path, overwrite: true);
            SecureJournalDirectory.RestrictExistingFile(path);
            return path;
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}
