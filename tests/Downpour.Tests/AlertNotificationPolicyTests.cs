using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class AlertNotificationPolicyTests
{
    private static int _counter;

    private static SecurityAlert Alert(string severity, string state = "Open", string title = "t")
    {
        var id = (Interlocked.Increment(ref _counter)).ToString("x64");
        var now = DateTimeOffset.UtcNow;
        return new SecurityAlert(id, title, severity, "T1", SecurityFindingCatalog.Persistence, new string('a', 32), 0, null, now, now, now, 1, state);
    }

    [Fact]
    public void FirstSnapshotIsABaselineAndNeverNotifies()
    {
        var policy = new AlertNotificationPolicy();
        Assert.Empty(policy.Next([Alert("CRITICAL"), Alert("HIGH")]));
    }

    [Fact]
    public void OnlyNewOpenHighOrCriticalAlertsNotifyOnce()
    {
        var policy = new AlertNotificationPolicy();
        var existing = Alert("CRITICAL");
        policy.Next([existing]);

        var critical = Alert("CRITICAL", title: "boom");
        var notifications = policy.Next([existing, critical, Alert("MEDIUM"), Alert("HIGH", state: "Suppressed")]);
        var single = Assert.Single(notifications);
        Assert.Equal("CRITICAL", single.HighestSeverity);
        Assert.Equal("boom", single.Body);
        Assert.StartsWith("CRITICAL: Persistence", single.Title);

        Assert.Empty(policy.Next([existing, critical]));
    }

    [Fact]
    public void BurstsAreCombinedIntoOneNotification()
    {
        var policy = new AlertNotificationPolicy();
        policy.Next([]);
        var burst = Enumerable.Range(0, 5).Select(i => Alert(i == 0 ? "CRITICAL" : "HIGH")).ToArray();
        var summary = Assert.Single(policy.Next(burst));
        Assert.Equal(5, summary.Count);
        Assert.Equal("CRITICAL", summary.HighestSeverity);
        Assert.Contains("1 critical, 4 high", summary.Body);
    }

    [Theory]
    [InlineData("CRITICAL", false, true)]
    [InlineData("HIGH", false, false)]
    [InlineData("HIGH", true, true)]
    [InlineData("MEDIUM", true, false)]
    public void SoundThresholdMatchesV29(string severity, bool includeHigh, bool expected) =>
        Assert.Equal(expected, AlertNotificationPolicy.ShouldSound(severity, includeHigh));

    [Fact]
    public void BeepPatternsMatchV29()
    {
        Assert.Equal(6, AlertNotificationPolicy.BeepPattern("CRITICAL").Count);
        Assert.Equal((1000, 300), AlertNotificationPolicy.BeepPattern("CRITICAL")[0]);
        Assert.Equal([(880, 500)], AlertNotificationPolicy.BeepPattern("HIGH"));
        Assert.Equal([(660, 200)], AlertNotificationPolicy.BeepPattern("LOW"));
    }
}
