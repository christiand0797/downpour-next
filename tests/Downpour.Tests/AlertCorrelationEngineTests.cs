using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class AlertCorrelationEngineTests
{
    [Fact]
    public void CorrelatesServiceInstallationAcrossChannelsWithinTwoMinutes()
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-10);
        var system = Alert("System", 7045, now, 101);
        var security = Alert("Security", 4697, now.AddMinutes(1), 202);
        var snapshot = Snapshot(DateTimeOffset.UtcNow, system, security);

        var finding = Assert.Single(AlertCorrelationEngine.Correlate(snapshot));

        Assert.Equal("service-install-cross-log", finding.RuleId);
        Assert.Equal("HIGH", finding.Severity);
        Assert.Equal(new[] { system.AlertId, security.AlertId }.Order(StringComparer.Ordinal), finding.EvidenceAlertIds);
        Assert.Contains("Time-proximate", finding.Limitation, StringComparison.Ordinal);
        Assert.Contains("shared operation identifier", finding.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public void CorrelatesLogClearEventsButDoesNotPairAnAlertMoreThanOnce()
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-10);
        var sec1 = Alert("Security", 1102, now, 1);
        var sec2 = Alert("Security", 1102, now.AddMinutes(1), 2);
        var sys1 = Alert("System", 104, now.AddSeconds(5), 3);
        var sys2 = Alert("System", 104, now.AddMinutes(9), 4);

        var findings = AlertCorrelationEngine.Correlate(Snapshot(DateTimeOffset.UtcNow, sec1, sec2, sys1, sys2));

        Assert.Equal(2, findings.Count);
        Assert.All(findings, finding => Assert.Equal("event-log-clear-cross-log", finding.RuleId));
        Assert.Equal(4, findings.SelectMany(finding => finding.EvidenceAlertIds).Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(findings, finding => finding.EvidenceAlertIds.Contains(sec1.AlertId) && finding.EvidenceAlertIds.Contains(sys1.AlertId));
        Assert.Contains("may describe different actions", findings[0].Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public void DoesNotCorrelateOutsideRuleWindowOrSuppressedEvidence()
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-3);
        var farSystem = Alert("System", 7045, now, 1);
        var farSecurity = Alert("Security", 4697, now.AddMinutes(3), 2);
        var suppressed = Alert("System", 7045, now, 3, state: "Suppressed");
        var nearSecurity = Alert("Security", 4697, now.AddSeconds(30), 4);

        var findings = AlertCorrelationEngine.Correlate(Snapshot(DateTimeOffset.UtcNow, farSystem, farSecurity, suppressed, nearSecurity));

        var finding = Assert.Single(findings);
        Assert.Contains(farSystem.AlertId, finding.EvidenceAlertIds);
        Assert.Contains(nearSecurity.AlertId, finding.EvidenceAlertIds);
        Assert.DoesNotContain(suppressed.AlertId, finding.EvidenceAlertIds);
    }

    [Fact]
    public void FindingIdentityIsStableAndInvalidSnapshotIsRejected()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = new[] { Alert("Security", 1102, now, 1), Alert("System", 104, now.AddSeconds(2), 2) };
        var snapshot = Snapshot(now, alerts);

        var first = Assert.Single(AlertCorrelationEngine.Correlate(snapshot));
        var second = Assert.Single(AlertCorrelationEngine.Correlate(snapshot with { CapturedAtUtc = now.AddSeconds(1) }));

        Assert.Equal(first.CorrelationId, second.CorrelationId);
        Assert.Throws<InvalidDataException>(() => AlertCorrelationEngine.Correlate(snapshot with { TotalCount = -1 }));
    }

    [Fact]
    public void CorrelatesAccountCreationBeforeGroupChangeOnlyInOrder()
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-20);
        var created = Alert("Security", 4720, now, 1);
        var added = Alert("Security", 4732, now.AddMinutes(5), 2);

        var finding = Assert.Single(AlertCorrelationEngine.Correlate(Snapshot(DateTimeOffset.UtcNow, created, added)));
        Assert.Equal("account-creation-group-change", finding.RuleId);
        Assert.Equal("T1098", finding.Technique);

        // Group membership added before the account existed is not this sequence.
        var earlyAdd = Alert("Security", 4732, now, 3);
        var lateCreate = Alert("Security", 4720, now.AddMinutes(5), 4);
        var reversed = AlertCorrelationEngine.Correlate(Snapshot(DateTimeOffset.UtcNow, earlyAdd, lateCreate));
        Assert.DoesNotContain(reversed, item => item.RuleId == "account-creation-group-change");
    }

    [Fact]
    public void CorrelatesDefenderDetectionBeforeServiceInstallationWithinThirtyMinutes()
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-45);
        var detection = Alert("Microsoft-Windows-Windows Defender/Operational", 1116, now, 1);
        var install = Alert("System", 7045, now.AddMinutes(10), 2);

        var finding = Assert.Single(AlertCorrelationEngine.Correlate(Snapshot(DateTimeOffset.UtcNow, detection, install)));
        Assert.Equal("defender-detection-service-install", finding.RuleId);
        Assert.Contains("may be unrelated", finding.Limitation, StringComparison.Ordinal);

        var far = Alert("System", 7045, now.AddMinutes(40), 3);
        Assert.DoesNotContain(AlertCorrelationEngine.Correlate(Snapshot(DateTimeOffset.UtcNow, detection, far)),
            item => item.RuleId == "defender-detection-service-install");
    }

    [Fact]
    public void CorrelatesFailedLogonBurstBeforeRemoteDesktopAuthentication()
    {
        var now = DateTimeOffset.UtcNow.AddMinutes(-10);
        var burst = Alert("Security", 4625, now, 1);
        var rdp = Alert("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149, now.AddMinutes(2), 2);

        var finding = Assert.Single(AlertCorrelationEngine.Correlate(Snapshot(DateTimeOffset.UtcNow, burst, rdp)));
        Assert.Equal("failed-logon-rdp-auth", finding.RuleId);
        Assert.Contains("five-minute burst", finding.Limitation, StringComparison.Ordinal);
    }

    private static SecurityAlertSnapshot Snapshot(DateTimeOffset capturedAt, params SecurityAlert[] alerts) =>
        new(1, capturedAt, alerts.Length, alerts, []);

    private static SecurityAlert Alert(string channel, int eventId, DateTimeOffset eventTime, long recordId, string state = "Open")
    {
        Assert.True(SecurityEventCatalog.TryGetRule(channel, eventId, out var rule));
        return new SecurityAlert(
            Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{channel}:{eventId}:{recordId}"))),
            rule.Summary, rule.Severity, rule.Technique, channel, "Downpour test provider", eventId, recordId,
            eventTime, eventTime, eventTime, 1, state);
    }
}
