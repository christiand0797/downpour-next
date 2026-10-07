using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class CognitiveImmuneSystemCoordinatorTests
{
    [Fact]
    public void MissingSourcesRemainUnknown()
    {
        var result = CognitiveImmuneSystemCoordinator.Assess(null, null, null);
        Assert.Equal("Unavailable", result.Status);
        Assert.Null(result.OpenAlerts);
        Assert.Null(result.UrgentOpenAlerts);
        Assert.Null(result.StoredAlerts);
        Assert.Null(result.ObservedTechniques);
        Assert.Empty(result.RecentAlerts);
        Assert.Empty(result.Correlations);
        Assert.Contains(result.Warnings, w => w.Contains("not absence"));
        var report = CognitiveImmuneSystemCoordinator.CreateReport(result, null);
        Assert.Contains("unknown", report);
        Assert.Contains("not checked", report);
        Assert.DoesNotContain("94%", report);
    }

    [Fact]
    public void CountsRespectStateVerificationAndReturnedWindow()
    {
        var rows = new[] { Alert('a', "Open", true), Alert('b', "Acknowledged", true), Alert('c', "Suppressed", true), Alert('d', "Open", false) };
        var result = CognitiveImmuneSystemCoordinator.Assess(new(1, DateTimeOffset.UtcNow, 9000, rows, []), null, new(1, false, false));
        Assert.Equal(9000, result.StoredAlerts);
        Assert.Equal(4, result.ReviewedAlerts);
        Assert.Equal(2, result.OpenAlerts);
        Assert.Equal(2, result.UrgentOpenAlerts);
        Assert.Equal(2, result.VerifiedActiveAlerts);
        Assert.Equal(1, result.SuppressedAlerts);
        Assert.Equal(1, result.ObservedTechniques);
        Assert.Contains(result.Warnings, w => w.Contains("truncated"));
        Assert.Contains(result.Sources, s => s.Name.Contains("PowerShell") && s.Status == "Disabled");
    }

    [Fact]
    public void MalformedAndStaleSnapshotsAreNotCounted()
    {
        var now = DateTimeOffset.UtcNow;
        var stale = new SecurityAlertSnapshot(1, now.AddHours(-1), 0, [], []);
        Assert.Null(CognitiveImmuneSystemCoordinator.Assess(stale, null, null).ReviewedAlerts);
        var forged = new SecurityAlertSnapshot(1, now, 1, [Alert('a', "Open", false) with { Title = "Forged malware" }], []);
        Assert.Null(CognitiveImmuneSystemCoordinator.Assess(forged, null, null).UrgentOpenAlerts);
    }

    [Fact]
    public void EmptyValidWindowReportsZeroWithoutProtectionVerdict()
    {
        var result = CognitiveImmuneSystemCoordinator.Assess(new(1, DateTimeOffset.UtcNow, 0, [], ["AMSI unavailable"]), null, null);
        Assert.Equal(0, result.OpenAlerts);
        Assert.Equal("Partial", result.Status);
        Assert.Contains("AMSI unavailable", result.Warnings);
        Assert.Contains("does not measure containment", CognitiveImmuneSystemCoordinator.CreateReport(result, null));
    }

    [Fact]
    public void RecentWindowIsBoundedAndSorted()
    {
        var rows = Enumerable.Range(1, 50).Select(i => Alert('a', "Open", false) with { AlertId = i.ToString("x64"), LastSeenUtc = DateTimeOffset.UtcNow.AddSeconds(-i) }).ToArray();
        var result = CognitiveImmuneSystemCoordinator.Assess(new(1, DateTimeOffset.UtcNow, 50, rows, []), null, null);
        Assert.Equal(32, result.RecentAlerts.Count);
        Assert.Equal(rows[0].AlertId, result.RecentAlerts[0].AlertId);
    }

    private static SecurityAlert Alert(char id, string state, bool verified)
    {
        var now = DateTimeOffset.UtcNow;
        SecurityEventCatalog.TryGetRule("System", 7045, out var rule);
        return new(new string(id, 64), rule.Summary, rule.Severity, rule.Technique, "System", "Service Control Manager", 7045,
            id, now.AddMinutes(-2), now.AddMinutes(-2), now.AddMinutes(-1), 1, state, verified);
    }
}
