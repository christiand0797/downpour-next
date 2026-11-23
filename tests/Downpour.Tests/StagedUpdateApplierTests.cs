using Downpour.Core;

namespace Downpour.Tests;

/// <summary>
/// Proves the update apply/rollback path, including the case that was never exercised: a file that cannot be replaced
/// because another process holds it open.
/// </summary>
public sealed class StagedUpdateApplierTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "downpour-apply-" + Guid.NewGuid().ToString("N"));

    public StagedUpdateApplierTests()
    {
        Directory.CreateDirectory(Install);
        Directory.CreateDirectory(Stage);
        Directory.CreateDirectory(Backup);
    }

    private string Install => Path.Combine(_root, "install");
    private string Stage => Path.Combine(_root, "stage");
    private string Backup => Path.Combine(_root, "backup");

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
    }

    private void Write(string relative, string content, string area = "install")
    {
        var path = Path.Combine(_root, area, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private string? Read(string relative, string area = "install")
    {
        var path = Path.Combine(_root, area, relative);
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    [Fact]
    public void ReplacesFilesAndKeepsThePreviousCopy()
    {
        Write("a.txt", "old-a");
        Write("sub/b.txt", "old-b");
        Write("a.txt", "new-a", "stage");
        Write("sub/b.txt", "new-b", "stage");

        var report = StagedUpdateApplier.Apply(Install, Stage, Backup, ["a.txt", "sub/b.txt"]);

        Assert.Equal(2, report.FilesReplaced);
        Assert.Equal(0, report.FilesRestored);
        Assert.Empty(report.NotRestored);
        Assert.Equal("new-a", Read("a.txt"));
        Assert.Equal("new-b", Read("sub/b.txt"));
        Assert.Equal("old-a", Read("a.txt", "backup"));
        Assert.Equal("old-b", Read("sub/b.txt", "backup"));
        Assert.Empty(Directory.GetFiles(_root, "*.downpour-update-*", SearchOption.AllDirectories));
    }

    [Fact]
    public void ALockedFileStopsTheApplyAndEarlierFilesAreRestored()
    {
        Write("a.txt", "old-a");
        Write("b.txt", "old-b");
        Write("c.txt", "old-c");
        Write("a.txt", "new-a", "stage");
        Write("b.txt", "new-b", "stage");
        Write("c.txt", "new-c", "stage");

        StagedUpdateApplyException exception;
        using (var locked = new FileStream(Path.Combine(Install, "b.txt"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            exception = Assert.Throws<StagedUpdateApplyException>(
                () => StagedUpdateApplier.Apply(Install, Stage, Backup, ["a.txt", "b.txt", "c.txt"]));

        Assert.Equal("b.txt", exception.FailedFile);
        Assert.Equal(1, exception.Report.FilesReplaced);
        Assert.Equal(1, exception.Report.FilesRestored);
        Assert.Empty(exception.Report.NotRestored);
        Assert.Equal("old-a", Read("a.txt"));
        Assert.Equal("old-b", Read("b.txt"));
        Assert.Equal("old-c", Read("c.txt"));
        Assert.Equal("new-a", Read("a.txt", "stage"));
    }

    [Fact]
    public void AFileThatCannotBeBackedUpIsLeftUnchangedAndNotCounted()
    {
        Write("a.txt", "old-a");
        Write("b.txt", "old-b");
        Write("a.txt", "new-a", "stage");
        Write("b.txt", "new-b", "stage");

        StagedUpdateApplyException exception;
        using (var locked = new FileStream(Path.Combine(Install, "a.txt"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            exception = Assert.Throws<StagedUpdateApplyException>(
                () => StagedUpdateApplier.Apply(Install, Stage, Backup, ["a.txt", "b.txt"]));

        Assert.Equal(0, exception.Report.FilesReplaced);
        Assert.Equal(0, exception.Report.FilesRestored);
        Assert.Equal("old-a", Read("a.txt"));
        Assert.Equal("old-b", Read("b.txt"));
    }

    [Fact]
    public void AFailedRestartRestoresEveryFileItReplaced()
    {
        Write("a.txt", "old-a");
        Write("deep/c.txt", "old-c");
        Write("a.txt", "new-a", "stage");
        Write("deep/c.txt", "new-c", "stage");

        var exception = Assert.Throws<StagedUpdateApplyException>(() => StagedUpdateApplier.Apply(
            Install, Stage, Backup, ["a.txt", "deep/c.txt"],
            () => throw new InvalidOperationException("The updated Downpour app could not be restarted.")));

        Assert.Equal(2, exception.Report.FilesReplaced);
        Assert.Equal(2, exception.Report.FilesRestored);
        Assert.Empty(exception.Report.NotRestored);
        Assert.Equal("old-a", Read("a.txt"));
        Assert.Equal("old-c", Read("deep/c.txt"));
        Assert.Equal("new-a", Read("a.txt", "stage"));
    }

    [Fact]
    public void ARestoreThatItselfFailsIsCountedAndNamed()
    {
        Write("a.txt", "old-a");
        Write("b.txt", "old-b");
        Write("a.txt", "new-a", "stage");
        Write("b.txt", "new-b", "stage");

        // Both files are replaced, then the restart fails while the first replacement is held open for writing. The rollback
        // restores b.txt and is refused a.txt, which is the branch a real mixed installation would take.
        FileStream? held = null;
        var exception = Assert.Throws<StagedUpdateApplyException>(() => StagedUpdateApplier.Apply(
            Install, Stage, Backup, ["a.txt", "b.txt"], () =>
            {
                held = new FileStream(Path.Combine(Install, "a.txt"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                throw new InvalidOperationException("The updated Downpour app could not be restarted.");
            }));

        try
        {
            Assert.Equal(2, exception.Report.FilesReplaced);
            Assert.Equal(1, exception.Report.FilesRestored);
            Assert.Equal(new[] { "a.txt" }, exception.Report.NotRestored);
            Assert.Contains("1 of 2", exception.Message);
            Assert.Contains("restored 1", exception.Report.Describe());
            Assert.Contains("could not be restored: a.txt", exception.Report.Describe());
        }
        finally
        {
            held?.Dispose();
        }

        // The file the filesystem refused keeps the new bytes: the report says so instead of implying a clean rollback.
        Assert.Equal("new-a", Read("a.txt"));
        Assert.Equal("old-b", Read("b.txt"));
        Assert.Empty(Directory.GetFiles(_root, "*.downpour-update-*", SearchOption.AllDirectories));
    }

    [Fact]
    public void ARefusalBeforeTheFirstWriteSaysNothingNeededRestoring()
    {
        var report = new StagedUpdateApplyReport(0, 0, []);

        Assert.Equal("No installed file had been replaced, so nothing needed to be restored.", report.Describe());
        Assert.Equal("Replaced 7 file(s) and restored 7.", new StagedUpdateApplyReport(7, 7, []).Describe());
    }

    [Fact]
    public void AFailedApplyRemovesFilesThatDidNotExistBefore()
    {
        Write("b.txt", "old-b");
        Write("added.txt", "brand-new", "stage");
        Write("b.txt", "new-b", "stage");

        using (var locked = new FileStream(Path.Combine(Install, "b.txt"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            Assert.Throws<StagedUpdateApplyException>(() => StagedUpdateApplier.Apply(Install, Stage, Backup, ["added.txt", "b.txt"]));

        Assert.Null(Read("added.txt"));
        Assert.Equal("old-b", Read("b.txt"));
    }

    [Fact]
    public void AnUnsafePathOrMissingStagedFileIsRefusedBeforeAnythingChanges()
    {
        Write("a.txt", "old-a");
        Write("a.txt", "new-a", "stage");

        Assert.Throws<InvalidDataException>(() => StagedUpdateApplier.Apply(Install, Stage, Backup, ["a.txt", "../escape.txt"]));
        Assert.Equal("old-a", Read("a.txt"));
        Assert.Null(Read(Path.Combine("..", "escape.txt"), "install"));

        Assert.Throws<InvalidDataException>(() => StagedUpdateApplier.Apply(Install, Stage, Backup, ["a.txt", "missing.txt"]));
        Assert.Equal("old-a", Read("a.txt"));
    }
}
