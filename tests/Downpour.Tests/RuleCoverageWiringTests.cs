using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

/// <summary>
/// The built-in rule catalog is only useful if a rule that cannot fire on this PC is visible. These tests cover the
/// stored channel readability, the coverage summary built from it, and the strict contract the desktop validates.
/// </summary>
public sealed class RuleCoverageWiringTests
{
    [Fact]
    public async Task CoverageNamesRulesWhoseChannelCannotBeRead()
    {
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        // Nothing is claimed before readability has actually been measured.
        Assert.Null((await repository.ReadSnapshotAsync()).Coverage);

        await repository.SaveChannelHealthAsync([new ChannelReadStatus("System", true), new ChannelReadStatus("Security", false)]);
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 42,
            DateTimeOffset.UtcNow.AddMinutes(-1))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, [observation], 1, []));

        var snapshot = await repository.ReadSnapshotAsync();
        var coverage = snapshot.Coverage;
        Assert.NotNull(coverage);
        Assert.Equal(SecurityEventCatalog.WatchedEvents.Count, coverage!.Rules);
        Assert.Equal(coverage.Rules, coverage.CanFire + coverage.CannotFire + coverage.Silent + coverage.Unknown);
        Assert.Contains(coverage.Entries, entry =>
            entry.State == nameof(RuleState.CannotFire) && entry.Channel == "Security" && entry.EventId == 1102);
        // The readable channel's rule fired, so it is not reported as a blind spot.
        Assert.DoesNotContain(coverage.Entries, entry => entry.RuleId == "System:7045");
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
    }

    [Fact]
    public async Task RulesWhoseChannelsWereNotMeasuredAreNotCalledSilent()
    {
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        await repository.SaveChannelHealthAsync([new ChannelReadStatus("System", true)]);

        var coverage = (await repository.ReadSnapshotAsync()).Coverage!;
        // A fresh store has not watched a full window, so a zero match count is never reported as silence.
        Assert.Equal(0, coverage.Silent);
        Assert.DoesNotContain(coverage.Entries, entry => entry.State == nameof(RuleState.Silent));
        Assert.NotNull(coverage.ObservedSinceUtc);
        // The measured channel is readable, so its rules are counted as able to fire rather than as blind spots.
        Assert.DoesNotContain(coverage.Entries, entry => entry.Channel == "System");
        Assert.Equal(2, coverage.CanFire);
    }

    [Fact]
    public async Task ClientRejectsInconsistentOrOversizedCoverage()
    {
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        await repository.SaveChannelHealthAsync([new ChannelReadStatus("System", false)]);
        var snapshot = await repository.ReadSnapshotAsync();
        var coverage = snapshot.Coverage!;
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));

        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Coverage = coverage with { CannotFire = coverage.CannotFire + 1 } }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with
        {
            Coverage = coverage with { Entries = [coverage.Entries[0] with { State = "Blind" }] }
        }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with
        {
            Coverage = coverage with { Entries = Enumerable.Range(0, 65).Select(index => new AlertRuleCoverageEntry(
                $"System:{index}", "System", index, "CannotFire", "Channel is not collected on this PC.")).ToArray() }
        }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with
        {
            Coverage = coverage with { Rules = -1 }
        }));
    }
}
