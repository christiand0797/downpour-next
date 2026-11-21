using Downpour.Core;

namespace Downpour.Tests;

public sealed class UpdateJournalWiringTests
{
    [Fact]
    public void JournalRoundTripsAndTheHelperGateRequiresStaged()
    {
        var path = TemporaryPath();
        try
        {
            var now = DateTimeOffset.UtcNow;
            UpdateJournalStore.Begin(path, "0.1.33", now, "Downloaded 306,482,886 bytes; the published SHA-256 matched.");
            Assert.Throws<ArgumentException>(() => UpdateJournalStore.Advance(path, UpdateState.Verified, now));
            UpdateJournalStore.Advance(path, UpdateState.Verified, now, "1,075 extracted file digests recorded.");
            UpdateJournalStore.Advance(path, UpdateState.Staged, now, "1,075 files staged for v0.1.33.");

            var records = UpdateJournalStore.Load(path);
            Assert.Equal(3, records.Count);
            Assert.Equal(UpdateState.Staged, records[^1].State);
            Assert.Equal("0.1.33", records[^1].Version);
            Assert.Equal(UpdateState.Staged, UpdateJournalStore.RequireStaged(records, "0.1.33").State);
            Assert.Throws<InvalidDataException>(() => UpdateJournalStore.RequireStaged(records, "0.1.34"));
            Assert.Throws<InvalidDataException>(() => UpdateJournalStore.RequireStaged([], "0.1.33"));

            UpdateJournalStore.Advance(path, UpdateState.Applied, now, "Applied v0.1.33 and restarted Downpour.");
            Assert.Throws<InvalidDataException>(() => UpdateJournalStore.RequireStaged(UpdateJournalStore.Load(path), "0.1.33"));
        }
        finally
        {
            Delete(path);
        }
    }

    [Fact]
    public void JournalRefusesIllegalTransitionsAndMarksAnAbandonedCycle()
    {
        var path = TemporaryPath();
        try
        {
            var now = DateTimeOffset.UtcNow;
            UpdateJournalStore.Begin(path, "0.1.33", now);
            UpdateJournalStore.Advance(path, UpdateState.Verified, now, "package digest matched");
            Assert.Throws<InvalidOperationException>(() => UpdateJournalStore.Advance(path, UpdateState.Downloaded, now));

            UpdateJournalStore.Begin(path, "0.1.34", now.AddMinutes(1), "Downloaded the newer package.");
            var records = UpdateJournalStore.Load(path);
            Assert.Equal(UpdateState.RolledBack, records[^2].State);
            Assert.Contains("Abandoned", records[^2].Detail);
            Assert.Equal(UpdateState.Downloaded, records[^1].State);
            Assert.Equal("0.1.34", records[^1].Version);
        }
        finally
        {
            Delete(path);
        }
    }

    [Fact]
    public void JournalFailureRecordingOnlyTouchesInProgressRecords()
    {
        var path = TemporaryPath();
        try
        {
            var now = DateTimeOffset.UtcNow;
            Assert.Null(UpdateJournalStore.TryRecordFailure(path, now, "nothing was journaled"));
            UpdateJournalStore.Begin(path, "0.1.33", now);
            var rolled = UpdateJournalStore.TryRecordFailure(path, now, "IOException before apply; no package file was replaced.");
            Assert.NotNull(rolled);
            Assert.Equal(UpdateState.RolledBack, rolled!.State);
            Assert.Contains("previous build", UpdateStagingJournal.Recover(rolled));
            Assert.Null(UpdateJournalStore.TryRecordFailure(path, now, "already terminal"));

            UpdateJournalStore.Begin(path, "0.1.34", now);
            UpdateJournalStore.Advance(path, UpdateState.Verified, now, "package digest matched");
            UpdateJournalStore.Advance(path, UpdateState.Staged, now);
            Assert.Equal(UpdateState.RolledBack, UpdateJournalStore.TryRecordFailure(path, now, "apply failed")!.State);
        }
        finally
        {
            Delete(path);
        }
    }

    [Fact]
    public void JournalStaysBoundedAndRejectsDamagedFiles()
    {
        var path = TemporaryPath();
        try
        {
            var now = DateTimeOffset.UtcNow;
            for (var index = 0; index < 40; index++)
                UpdateJournalStore.Begin(path, $"0.1.{index + 30}", now.AddMinutes(index), new string('d', 400));
            var records = UpdateJournalStore.Load(path);
            Assert.Equal(UpdateJournalStore.MaximumRecords, records.Count);
            Assert.All(records, record => Assert.True(record.Detail.Length <= UpdateJournalStore.MaximumDetailLength));
            Assert.Equal("0.1.69", records[^1].Version);

            File.WriteAllText(path, "{not json");
            Assert.Throws<InvalidDataException>(() => UpdateJournalStore.Load(path));
            File.WriteAllText(path, new string('x', UpdateJournalStore.MaximumFileBytes + 1));
            Assert.Throws<InvalidDataException>(() => UpdateJournalStore.Load(path));
            File.Delete(path);
            Assert.Empty(UpdateJournalStore.Load(path));
            Assert.Throws<ArgumentOutOfRangeException>(() => UpdateJournalStore.Begin(path, "not-a-version", now));
        }
        finally
        {
            Delete(path);
        }
    }

    private static string TemporaryPath() =>
        Path.Combine(Path.GetTempPath(), "downpour-update-journal-" + Guid.NewGuid().ToString("N"), "update-journal.json");

    private static void Delete(string path)
    {
        var directory = Path.GetDirectoryName(path)!;
        try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); } catch { }
    }
}
