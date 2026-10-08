using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatPulseTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 15, 40, 0, TimeSpan.Zero);

    private static SecurityAlert Alert(DateTimeOffset at, string severity = "LOW") =>
        new(Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N"), "t", severity, "T", "System", "p", 1, null, at, at, at, 1, "Open");

    /// <summary>Two findings every hour for five days, then whatever the test adds for the current hour.</summary>
    private static List<SecurityAlert> SteadyHistory()
    {
        var alerts = new List<SecurityAlert>();
        for (var h = 1; h <= 120; h++)
        {
            alerts.Add(Alert(Now.AddHours(-h)));
            alerts.Add(Alert(Now.AddHours(-h).AddMinutes(-20)));
        }
        return alerts;
    }

    [Fact]
    public void NewInstallIsLearning()
    {
        var reading = ThreatPulse.Compute([Alert(Now.AddMinutes(-10)), Alert(Now.AddHours(-2))], Now);
        Assert.Equal(ThreatPulseStates.Learning, reading.State);
        Assert.Equal(24, reading.Last24Hours.Count);
        Assert.Contains("more hour", reading.Detail);
    }

    [Fact]
    public void NormalActivityIsCalm()
    {
        var alerts = SteadyHistory();
        alerts.Add(Alert(Now.AddMinutes(-5)));
        alerts.Add(Alert(Now.AddMinutes(-15)));
        var reading = ThreatPulse.Compute(alerts, Now);
        Assert.Equal(ThreatPulseStates.Calm, reading.State);
        Assert.Equal(2, reading.Normal);
        Assert.Equal(2, reading.ThisHour);
    }

    [Fact]
    public void BurstAboveTheLearnedNormalIsASpike()
    {
        var alerts = SteadyHistory();
        for (var i = 0; i < 15; i++) alerts.Add(Alert(Now.AddMinutes(-i * 2), i < 3 ? "HIGH" : "LOW"));
        var reading = ThreatPulse.Compute(alerts, Now);
        Assert.Equal(ThreatPulseStates.Spike, reading.State);
        Assert.Equal(15, reading.ThisHour);
        Assert.Equal(3, reading.ThisHourSerious);
        Assert.Contains("normal", reading.Detail);
        Assert.Equal(15, reading.Last24Hours[^1].Count);
    }

    [Fact]
    public void QuietPcNeedsAtLeastAFewFindingsToSpike()
    {
        var alerts = new List<SecurityAlert> { Alert(Now.AddDays(-5)) };
        alerts.Add(Alert(Now.AddMinutes(-3)));
        alerts.Add(Alert(Now.AddMinutes(-4)));
        Assert.NotEqual(ThreatPulseStates.Spike, ThreatPulse.Compute(alerts, Now).State);
        alerts.AddRange(Enumerable.Range(0, 3).Select(i => Alert(Now.AddMinutes(-i))));
        Assert.Equal(ThreatPulseStates.Spike, ThreatPulse.Compute(alerts, Now).State);
    }

    [Fact]
    public void SeriousFindingMakesTheHourElevated()
    {
        var alerts = SteadyHistory();
        alerts.Add(Alert(Now.AddMinutes(-1), "CRITICAL"));
        Assert.Equal(ThreatPulseStates.Elevated, ThreatPulse.Compute(alerts, Now).State);
    }

    [Fact]
    public async Task ServiceCountsEveryAlertPerHourNotOnlyTheSnapshotRows()
    {
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var repository = new Downpour.Service.SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow;
        var hour = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero);
        var events = Enumerable.Range(1, 4).Select(i =>
            Downpour.Service.SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 500 + i, hour.AddMinutes(-60 + i))!).ToArray();
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, events, 1, []));

        var snapshot = await repository.ReadSnapshotAsync();
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
        var bucket = Assert.Single(snapshot.Hourly!);
        Assert.Equal(hour.AddHours(-1), bucket.HourUtc);
        Assert.Equal(4, bucket.Count);
        Assert.Equal(4, bucket.Serious);
        Assert.Equal(4, ThreatPulse.Compute(snapshot, now).Last24Hours[^2].Count);
    }

    [Fact]
    public void ClientRejectsMalformedHourlyCounts()
    {
        var now = DateTimeOffset.UtcNow;
        var snapshot = new SecurityAlertSnapshot(1, now, 0, [], [], [new AlertHourCount(new DateTimeOffset(2026, 10, 8, 1, 0, 0, TimeSpan.Zero), 3, 1)]);
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Hourly = [new AlertHourCount(now, 2, 3)] }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Hourly = [new AlertHourCount(now, -1, 0)] }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Hourly = Enumerable.Range(0, 200).Select(i => new AlertHourCount(now, 1, 0)).ToArray() }));
    }

    [Fact]
    public void FutureAndAncientAlertsAreIgnored()
    {
        var reading = ThreatPulse.Compute([Alert(Now.AddDays(3)), Alert(Now.AddDays(-30))], Now);
        Assert.All(reading.Last24Hours, hour => Assert.Equal(0, hour.Count));
    }
}
