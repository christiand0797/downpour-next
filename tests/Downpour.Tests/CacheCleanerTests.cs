using Downpour.Core;

namespace Downpour.Tests;

public sealed class CacheCleanerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "dp-cache-" + Guid.NewGuid().ToString("N"));

    public CacheCleanerTests()
    {
        Write(@"threat-db\loldrivers.v1.cache", 100);
        Write(@"threat-db\loldrivers.v1.cache.abc.tmp", 50);
        Write(@"threat-intel\cisa-kev.v1.cache", 30);
        Write(@"logs\service.log", 10);
        Write(@"logs\desktop-crash.log", 10);
        Write(@"updates\0.1.20\package.zip", 70);
        Write(@"emergency_snapshots\emergency_snapshot_1.json", 20);
        Write(@"state\dns-baseline.v1.json", 5);
        Write(@"state\intel-results.v1.json", 5);
        // Never removable.
        Write(@"state\action-audit.v1.jsonl", 5);
        Write(@"state\action-audit.v1.jsonl.key", 5);
        Write(@"state\alerts.v1.db", 5);
        Write(@"state\quarantine\obj-1.dpq", 5);
        Write(@"state\quarantine\obj-1.tmp", 5);
        Write(@"state\quarantine\vault.key", 5);
        Write("preferences.v1.ini", 5);
    }

    private void Write(string relative, int bytes)
    {
        var path = Path.Combine(_root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]);
    }

    private bool Exists(string relative) => File.Exists(Path.Combine(_root, relative));

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public void MeasureCountsEachCategory()
    {
        var usage = CacheCleaner.Measure(_root).ToDictionary(u => u.Category.Id);

        Assert.Equal(100, usage[CacheCleaner.ThreatDatabases].Bytes);
        Assert.Equal(50, usage[CacheCleaner.TemporaryFiles].Bytes);
        Assert.Equal(2, usage[CacheCleaner.Logs].Files);
        Assert.Equal(35, usage[CacheCleaner.VulnerabilityCatalog].Bytes);
        Assert.Equal(70, usage[CacheCleaner.UpdateLeftovers].Bytes);
    }

    [Fact]
    public void CleaningEverythingNeverTouchesProtectedFilesOrQuarantine()
    {
        var result = CacheCleaner.Clean(_root, CacheCleaner.Categories.Select(c => c.Id));

        Assert.True(result.FilesDeleted >= 9);
        Assert.False(Exists(@"threat-db\loldrivers.v1.cache.abc.tmp"));
        Assert.False(Exists(@"threat-db\loldrivers.v1.cache"));
        Assert.False(Exists(@"updates\0.1.20\package.zip"));
        Assert.False(Directory.Exists(Path.Combine(_root, "updates")));
        foreach (var kept in new[] { @"state\action-audit.v1.jsonl", @"state\action-audit.v1.jsonl.key", @"state\alerts.v1.db",
                     @"state\quarantine\obj-1.dpq", @"state\quarantine\obj-1.tmp", @"state\quarantine\vault.key", "preferences.v1.ini" })
            Assert.True(Exists(kept), kept);
    }

    [Fact]
    public void DefaultSelectionKeepsDatabasesBaselinesAndSnapshots()
    {
        CacheCleaner.Clean(_root, CacheCleaner.Categories.Where(c => c.SelectedByDefault).Select(c => c.Id));

        Assert.False(Exists(@"threat-db\loldrivers.v1.cache.abc.tmp"));
        Assert.True(Exists(@"threat-db\loldrivers.v1.cache"));
        Assert.True(Exists(@"state\dns-baseline.v1.json"));
        Assert.True(Exists(@"emergency_snapshots\emergency_snapshot_1.json"));
    }

    [Fact]
    public void FilesInUseAreSkippedAndKeptFileIsKept()
    {
        using (File.Open(Path.Combine(_root, @"logs\service.log"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var result = CacheCleaner.Clean(_root, [CacheCleaner.Logs]);
            Assert.Equal(1, result.FilesInUse);
        }
        Assert.True(Exists(@"logs\service.log"));
        Assert.False(Exists(@"logs\desktop-crash.log"));
    }

    [Fact]
    public void UnknownCategoriesAndMissingRootsDoNothing()
    {
        Assert.Equal(0, CacheCleaner.Clean(_root, ["../../Windows"]).FilesDeleted);
        Assert.All(CacheCleaner.Measure(Path.Combine(_root, "missing")), u => Assert.Equal(0, u.Files));
    }
}
