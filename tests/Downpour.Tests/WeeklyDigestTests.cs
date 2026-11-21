using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class WeeklyDigestTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Build_KeepsUnknownInputsOutOfTheQuietClaim()
    {
        var digest = WeeklyDigest.Build(new DigestInputs(Now.AddDays(-7), Now,
            NewAutostarts: null, HiddenMatches: 0, SuppressionsExpired: 0, SensorsBlind: 0,
            FindingsAwaitingReview: 0, FindingsResolved: null, OldestOpenDays: 0, MostActiveRule: null));

        Assert.DoesNotContain("quiet week", digest);
        Assert.Contains("## Not recorded", digest);
        Assert.Contains("Autostart changes are not recorded", digest);
        Assert.Contains("Rule activity is unavailable", digest);
        Assert.Contains("Nothing is waiting for review", digest);
    }

    [Fact]
    public void Build_OnlyCallsAWeekQuietWhenEveryQuietFactIsKnown()
    {
        var digest = WeeklyDigest.Build(new DigestInputs(Now.AddDays(-7), Now, 0, 0, 0, 0, 0, 0, 0, ""));
        Assert.Contains("quiet week", digest);
        Assert.Contains("Nothing is waiting for review", digest);
        Assert.DoesNotContain("## Not recorded", digest);
    }

    [Fact]
    public void Build_ReportsAcknowledgementsSeparatelyFromResolution()
    {
        var digest = WeeklyDigest.Build(new DigestInputs(Now.AddDays(-7), Now, 0, 1, 0, 0, 3, null, 5, "Rule A", FindingsAcknowledged: 4));
        Assert.Contains("4 finding(s) were acknowledged this week", digest);
        Assert.Contains("oldest has been open 5 day", digest);
        Assert.Contains("1 match(es) were hidden", digest);
        Assert.DoesNotContain("were resolved this week", digest);
    }

    [Fact]
    public void Build_RefusesABackwardsWindow() =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            WeeklyDigest.Build(new DigestInputs(Now, Now.AddDays(-1), 0, 0, 0, 0, 0, 0, 0, "")));

    [Fact]
    public void FileName_UsesTheIsoWeekAndIsoYear()
    {
        Assert.Equal("weekly-2026-W47.md", WeeklyDigestCalendar.FileName(Now));
        Assert.Equal("weekly-2020-W53.md", WeeklyDigestCalendar.FileName(new DateTimeOffset(2021, 1, 1, 8, 0, 0, TimeSpan.Zero)));
        Assert.StartsWith("weekly-", WeeklyDigestCalendar.FileName(DateTimeOffset.MinValue));
    }

    [Fact]
    public void FromFacts_NeverInventsAutostartsOrResolutions()
    {
        var facts = new WeeklyDigestFacts(12, 9, 3, 4, 2, 1, 2, 7, 0, 0, 5, Now.AddDays(-30), "Windows service installed");
        var inputs = WeeklyDigestInputs.FromFacts(facts, Now.AddDays(-7), Now);

        Assert.Null(inputs.NewAutostarts);
        Assert.Null(inputs.FindingsResolved);
        Assert.Equal(5, inputs.SensorsBlind);
        Assert.Equal(3, inputs.FindingsAwaitingReview);
        Assert.Equal(2, inputs.FindingsAcknowledged);
        Assert.Equal(7, inputs.HiddenMatches);
        Assert.Equal("Windows service installed", inputs.MostActiveRule);
    }

    [Fact]
    public async Task RepositoryReportsOnlyStoredWeeklyFacts()
    {
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var captured = DateTimeOffset.UtcNow;
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 42, captured.AddMinutes(-1))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, captured, [observation], 7, []));

        var facts = await repository.ReadWeeklyDigestFactsAsync(captured.AddHours(-1));

        Assert.Equal(1, facts.AlertsFirstSeen);
        Assert.Equal(1, facts.AlertsLastSeen);
        Assert.Equal(1, facts.OpenNow);
        Assert.Equal(0, facts.OldestOpenDays);

        // A window that opens after the row was stored must exclude it, and the unwindowed open count stays honest.
        var after = await repository.ReadWeeklyDigestFactsAsync(captured.AddMinutes(5));
        Assert.Equal(0, after.AlertsFirstSeen);
        Assert.Equal(0, after.AlertsLastSeen);
        Assert.Equal(1, after.OpenNow);
        Assert.Equal(0, facts.HiddenMatches);
        Assert.Equal(0, facts.SuppressionsActive);
        Assert.Equal(0, facts.EvictionsThisWeek);
        // No channel measurement exists in a fresh store, so readability is unknown rather than "zero blind sensors".
        Assert.Null(facts.SensorsBlind);
        Assert.Null(facts.ObservedSinceUtc);
        Assert.Contains("Windows service installed", facts.MostActiveRule);
    }

    [Fact]
    public async Task WorkerDefersUntilTheStoreHasWatchedAWeek()
    {
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var root = Path.Combine(Path.GetTempPath(), "downpour-digest-worker-" + Guid.NewGuid().ToString("N"));
        try
        {
            var writer = new WeeklyDigestWriter(root);
            var worker = new WeeklyDigestWorker(repository, writer, Microsoft.Extensions.Logging.Abstractions.NullLogger<WeeklyDigestWorker>.Instance);

            Assert.False(await worker.TryWriteAsync(CancellationToken.None));
            Assert.Empty(Directory.Exists(root) ? Directory.GetFiles(root) : []);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void WriterWritesOneBoundedFilePerIsoWeek()
    {
        var root = Path.Combine(Path.GetTempPath(), "downpour-digest-" + Guid.NewGuid().ToString("N"));
        try
        {
            var writer = new WeeklyDigestWriter(root);
            Assert.False(writer.ExistsFor(Now));

            var path = writer.Write(Now, "# summary\n");
            Assert.True(File.Exists(path));
            Assert.EndsWith("weekly-2026-W47.md", path);
            Assert.Equal("# summary\n", File.ReadAllText(path));

            writer.Write(Now, "# replaced\n");
            Assert.Equal("# replaced\n", File.ReadAllText(path));
            Assert.Throws<InvalidOperationException>(() => writer.Write(Now, new string('x', WeeklyDigestWriter.MaximumReportBytes + 1)));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }
}
