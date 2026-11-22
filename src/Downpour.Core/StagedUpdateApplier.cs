namespace Downpour.Core;

/// <summary>What an apply did: how many files it replaced, and whether each touched file was restored after a failure.</summary>
public sealed record StagedUpdateApplyReport(int FilesReplaced, int FilesRestored, IReadOnlyList<string> NotRestored);

/// <summary>
/// Raised when applying a staged update fails. The applier has already tried to restore every file it touched; the report
/// says how many it restored and names the ones the filesystem refused, so a caller never has to say "where possible"
/// without a number.
/// </summary>
public sealed class StagedUpdateApplyException : Exception
{
    public StagedUpdateApplyException(string message, string failedFile, Exception inner, StagedUpdateApplyReport report)
        : base(message, inner)
    {
        FailedFile = failedFile;
        Report = report;
    }

    /// <summary>The relative path whose step failed, so a person can see which file stopped the update.</summary>
    public string FailedFile { get; }

    public StagedUpdateApplyReport Report { get; }
}

/// <summary>
/// Replaces the files of an installed folder from a verified staging folder: every file it is about to overwrite is copied
/// to a backup first, and any failure restores each touched file in reverse order. It runs the caller's post-apply step
/// inside the same protected region, so a build that cannot restart is rolled back with the files.
/// This lives in Core so rollback can be proved against a locked file; the helper still owns the manifest, the journal
/// record and the restart, and the caller still validates every digest before this is reached.
/// </summary>
public static class StagedUpdateApplier
{
    private const int MaximumReportedFiles = 64;

    /// <param name="afterFilesApplied">
    /// Runs once every file is in place. If it throws — for example the new build does not start — every replaced file is
    /// restored and the failure is reported as <see cref="StagedUpdateApplyException"/>.
    /// </param>
    public static StagedUpdateApplyReport Apply(
        string installRoot,
        string stageRoot,
        string backupRoot,
        IReadOnlyList<string> relativeFiles,
        Action? afterFilesApplied = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(stageRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(backupRoot);
        ArgumentNullException.ThrowIfNull(relativeFiles);
        if (relativeFiles.Count == 0) throw new ArgumentException("There is nothing to apply.", nameof(relativeFiles));

        // Every path is checked, and every staged file must exist, before a single installed file is touched: a bad
        // manifest must not leave a half-updated folder behind.
        var plan = Plan(Path.GetFullPath(installRoot), Path.GetFullPath(stageRoot), Path.GetFullPath(backupRoot), relativeFiles);
        var changed = new List<Change>(plan.Count);
        var current = plan[0].Relative;
        try
        {
            foreach (var change in plan)
            {
                current = change.Relative;
                Directory.CreateDirectory(Path.GetDirectoryName(change.Destination)!);
                string? recordedBackup = null;
                if (File.Exists(change.Destination))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(change.Backup)!);
                    File.Copy(change.Destination, change.Backup, overwrite: false);
                    recordedBackup = change.Backup;
                }
                var temporary = change.Destination + ".downpour-update-" + Guid.NewGuid().ToString("N");
                changed.Add(change with { RecordedBackup = recordedBackup, Temporary = temporary });
                File.Copy(change.Staged, temporary, overwrite: false);
                File.Move(temporary, change.Destination, overwrite: true);
            }

            afterFilesApplied?.Invoke();
            return new StagedUpdateApplyReport(plan.Count, 0, []);
        }
        catch (Exception exception)
        {
            var restored = 0;
            var notRestored = new List<string>();
            for (var index = changed.Count - 1; index >= 0; index--)
            {
                var change = changed[index];
                try
                {
                    if (change.Temporary is { } temporary && File.Exists(temporary)) File.Delete(temporary);
                    if (change.RecordedBackup is { } backupFile && File.Exists(backupFile)) File.Copy(backupFile, change.Destination, overwrite: true);
                    // No backup means the file did not exist before this attempt, so a copy left behind is Downpour's own.
                    else if (File.Exists(change.Destination)) File.Delete(change.Destination);
                    restored++;
                }
                catch
                {
                    if (notRestored.Count < MaximumReportedFiles) notRestored.Add(change.Relative);
                }
            }
            throw new StagedUpdateApplyException(
                $"The update failed at {current}; {restored} of {changed.Count} touched file(s) were restored.",
                current, exception, new StagedUpdateApplyReport(changed.Count, restored, notRestored));
        }
    }

    private static List<Change> Plan(string root, string stage, string backup, IReadOnlyList<string> relativeFiles)
    {
        var plan = new List<Change>(relativeFiles.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var relative in relativeFiles)
        {
            if (string.IsNullOrWhiteSpace(relative) || relative.Length > 512)
                throw new InvalidDataException("A staged update path is empty or too long.");
            var local = relative.Replace('\\', '/').Replace('/', Path.DirectorySeparatorChar);
            var destination = Path.GetFullPath(Path.Combine(root, local));
            var staged = Path.GetFullPath(Path.Combine(stage, local));
            var backupFile = Path.GetFullPath(Path.Combine(backup, local));
            if (!UpdatePathPolicy.IsStrictChildPath(root, destination) ||
                !UpdatePathPolicy.IsStrictChildPath(stage, staged) ||
                !UpdatePathPolicy.IsStrictChildPath(backup, backupFile))
                throw new InvalidDataException("A staged update path escaped its folder.");
            if (!seen.Add(destination)) throw new InvalidDataException("A staged update repeats a file.");
            if (!File.Exists(staged)) throw new InvalidDataException("A staged update file is missing.");
            plan.Add(new Change(relative, staged, destination, backupFile, null, null));
        }
        return plan;
    }

    private sealed record Change(string Relative, string Staged, string Destination, string Backup, string? RecordedBackup, string? Temporary);
}
