using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class TimelineAttackDetectorTests
{
    [Fact]
    public void DetectsBruteForcePatternWithFiveOrMoreFailedLogons()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = Enumerable.Range(1, 5)
            .Select(i => CreateAlert("Security", 4625, now.AddSeconds(i * 10), i, "Failed logon attempt"))
            .ToArray();

        var findings = TimelineAttackDetector.Detect(alerts);

        var finding = Assert.Single(findings);
        Assert.Equal("CRITICAL", finding.Severity);
        Assert.Equal("T1110.001", finding.Technique);
        Assert.Equal("Brute Force Authentication Pattern", finding.Title);
        Assert.Equal(5, finding.EvidenceIds.Count);
    }

    [Fact]
    public void IgnoresFewerThanFiveFailedLogons()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = Enumerable.Range(1, 4)
            .Select(i => CreateAlert("Security", 4625, now.AddSeconds(i * 10), i, "Failed logon attempt"))
            .ToArray();

        var findings = TimelineAttackDetector.Detect(alerts);

        Assert.Empty(findings);
    }

    [Fact]
    public void DetectsAccountManipulationEvents()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = new[]
        {
            CreateAlert("Security", 4720, now, 1, "A user account was created"),
            CreateAlert("Security", 4728, now.AddMinutes(1), 2, "A member was added to a security group")
        };

        var findings = TimelineAttackDetector.Detect(alerts);

        var finding = Assert.Single(findings);
        Assert.Equal("HIGH", finding.Severity);
        Assert.Equal("T1098", finding.Technique);
        Assert.Equal("Privileged Account Manipulation", finding.Title);
        Assert.Equal(2, finding.EvidenceIds.Count);
    }

    [Fact]
    public void DetectsNewServiceInstallations()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = new[]
        {
            CreateAlert("System", 7045, now, 10, "A service was installed in the system"),
            CreateAlert("Security", 4697, now.AddSeconds(5), 11, "A service was installed in the system")
        };

        var findings = TimelineAttackDetector.Detect(alerts);

        var finding = Assert.Single(findings);
        Assert.Equal("HIGH", finding.Severity);
        Assert.Equal("T1543.003", finding.Technique);
        Assert.Equal("New Windows Service Installation", finding.Title);
        Assert.Equal(2, finding.EvidenceIds.Count);
    }

    [Fact]
    public void DetectsScheduledTaskPersistenceActivity()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = new[]
        {
            CreateAlert("Security", 4698, now, 20, "A scheduled task was created")
        };

        var findings = TimelineAttackDetector.Detect(alerts);

        var finding = Assert.Single(findings);
        Assert.Equal("HIGH", finding.Severity);
        Assert.Equal("T1053.005", finding.Technique);
        Assert.Equal("Scheduled Task Persistence Activity", finding.Title);
    }

    [Fact]
    public void DetectsExplicitCredentialBurstAboveThreshold()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = Enumerable.Range(1, 5)
            .Select(i => CreateAlert("Security", 4648, now.AddSeconds(i * 15), i + 30, "A logon was attempted using explicit credentials"))
            .ToArray();

        var findings = TimelineAttackDetector.Detect(alerts);

        var finding = Assert.Single(findings);
        Assert.Equal("MEDIUM", finding.Severity);
        Assert.Equal("T1078", finding.Technique);
        Assert.Equal("Explicit Credential Logon Burst", finding.Title);
        Assert.Equal(5, finding.EvidenceIds.Count);
    }

    [Fact]
    public void DetectsFirewallModifications()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = new[]
        {
            CreateAlert("Security", 4946, now, 40, "A rule has been added to the Windows Firewall exception list")
        };

        var findings = TimelineAttackDetector.Detect(alerts);

        var finding = Assert.Single(findings);
        Assert.Equal("MEDIUM", finding.Severity);
        Assert.Equal("T1562.004", finding.Technique);
        Assert.Equal("Firewall Rule Modification", finding.Title);
    }

    [Fact]
    public void GeneratesValidDarkThemedHtmlReport()
    {
        var now = DateTimeOffset.UtcNow;
        var alerts = new[]
        {
            CreateAlert("System", 7045, now, 100, "Service Installed"),
            CreateAlert("Security", 4624, now.AddMinutes(1), 101, "Successful Logon")
        };
        var findings = TimelineAttackDetector.Detect(alerts);

        var html = TimelineAttackDetector.GenerateHtmlReport(alerts, findings, "Test Downpour Timeline");

        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Contains("Test Downpour Timeline", html, StringComparison.Ordinal);
        Assert.Contains("Total Events: 2", html, StringComparison.Ordinal);
        Assert.Contains("Service Installed", html, StringComparison.Ordinal);
        Assert.Contains("7045", html, StringComparison.Ordinal);
        Assert.Contains("4624", html, StringComparison.Ordinal);
        Assert.Contains("T1543.003", html, StringComparison.Ordinal);
        Assert.EndsWith("</html>\r\n", html, StringComparison.Ordinal);
    }

    private static SecurityAlert CreateAlert(string channel, int eventId, DateTimeOffset time, long recordId, string title) =>
        new(
            $"alert_{channel}_{eventId}_{recordId}",
            title,
            "HIGH",
            "T1000",
            channel,
            "Microsoft-Windows-Security-Auditing",
            eventId,
            recordId,
            time,
            time,
            time,
            1,
            "Open");
}
