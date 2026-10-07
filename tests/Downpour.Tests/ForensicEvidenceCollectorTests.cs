using Downpour.Contracts;
using Downpour.Core;
using Newtonsoft.Json;
using Xunit;

namespace Downpour.Tests;

public sealed class ForensicEvidenceCollectorTests
{
    [Fact]
    public void CollectChainOfCustody_ReturnsValidHostAndTimestamp()
    {
        var coc = ForensicEvidenceCollector.CollectChainOfCustody();

        Assert.False(string.IsNullOrWhiteSpace(coc.Hostname));
        Assert.False(string.IsNullOrWhiteSpace(coc.OsDescription));
        Assert.False(string.IsNullOrWhiteSpace(coc.OsArchitecture));
        Assert.Contains("Downpour", coc.CollectorVersion);
        Assert.True(coc.CollectedAtUtc <= DateTimeOffset.UtcNow);
        Assert.True(coc.CollectedAtUtc >= DateTimeOffset.UtcNow.AddMinutes(-5));
    }

    [Fact]
    public void ComputeEvidenceIntegritySha256_IsDeterministic()
    {
        var coc = new ForensicChainOfCustody
        {
            Hostname = "TEST-HOST",
            OsDescription = "Windows 11 Test",
            OsArchitecture = "X64",
            CollectorVersion = "Downpour Next v0.1.14",
            CollectedAtUtc = new DateTimeOffset(2026, 10, 7, 12, 0, 0, TimeSpan.Zero),
            LocalIpAddresses = "192.168.1.100",
            MacAddresses = "00:11:22:33:44:55"
        };

        var artifacts = new List<ForensicArtifactItem>
        {
            new()
            {
                Category = "Account Compromise",
                Title = "Multiple Failed Logons",
                Detail = "Brute force pattern detected",
                Severity = "CRITICAL",
                Technique = "T1110.001",
                TimestampUtc = new DateTimeOffset(2026, 10, 7, 11, 55, 0, TimeSpan.Zero)
            },
            new()
            {
                Category = "Defender Tampering",
                Title = "Real-time protection disabled",
                Detail = "Defender Event 5001 observed",
                Severity = "HIGH",
                Technique = "T1562.001",
                TimestampUtc = new DateTimeOffset(2026, 10, 7, 11, 56, 0, TimeSpan.Zero)
            }
        };

        var ips = new List<string> { "203.0.113.195", "198.51.100.4" };

        var hash1 = ForensicEvidenceCollector.ComputeEvidenceIntegritySha256(coc, artifacts, ips);
        var hash2 = ForensicEvidenceCollector.ComputeEvidenceIntegritySha256(coc, artifacts, ips);

        Assert.Equal(hash1, hash2);
        Assert.Equal(64, hash1.Length); // 64 hex characters for SHA-256

        // Tampering with any artifact modifies the hash
        var tamperedArtifacts = new List<ForensicArtifactItem>
        {
            new()
            {
                Category = artifacts[0].Category,
                Title = artifacts[0].Title + " TAMPERED",
                Detail = artifacts[0].Detail,
                Severity = artifacts[0].Severity,
                Technique = artifacts[0].Technique,
                TimestampUtc = artifacts[0].TimestampUtc
            },
            artifacts[1]
        };

        var tamperedHash = ForensicEvidenceCollector.ComputeEvidenceIntegritySha256(coc, tamperedArtifacts, ips);
        Assert.NotEqual(hash1, tamperedHash);
    }

    [Fact]
    public async Task CollectAsync_ProducesValidEvidenceBundle()
    {
        // Calling CollectAsync with fast probe timeout handles unavailable services gracefully in milliseconds
        var bundle = await ForensicEvidenceCollector.CollectAsync(probeTimeout: TimeSpan.FromMilliseconds(50));

        Assert.NotNull(bundle);
        Assert.Equal(1, bundle.SchemaVersion);
        Assert.NotNull(bundle.ChainOfCustody);
        Assert.False(string.IsNullOrWhiteSpace(bundle.ChainOfCustody.Hostname));
        Assert.False(string.IsNullOrWhiteSpace(bundle.ChainOfCustody.EvidenceIntegritySha256));
        Assert.NotNull(bundle.Artifacts);
        Assert.NotNull(bundle.AttackerIps);
        Assert.NotNull(bundle.SuspiciousPersistenceItems);
        Assert.NotNull(bundle.SecurityAlertIds);
        Assert.Contains("law enforcement", bundle.LegalDisclaimer, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GenerateJsonBundle_IsRoundTripSerializable()
    {
        var coc = new ForensicChainOfCustody
        {
            Hostname = "SEC-WORKSTATION",
            OsDescription = "Microsoft Windows 11 Enterprise",
            OsArchitecture = "X64",
            CollectorVersion = "Downpour Next v0.1.14",
            CollectedAtUtc = DateTimeOffset.UtcNow,
            LocalIpAddresses = "10.0.0.50",
            MacAddresses = "AA:BB:CC:DD:EE:FF",
            EvidenceIntegritySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        };

        var bundle = new ForensicEvidenceBundle
        {
            SchemaVersion = 1,
            ChainOfCustody = coc,
            Artifacts =
            [
                new()
                {
                    Category = "Firewall Event",
                    Title = "Blocked Inbound Connection: 198.51.100.25:4444",
                    Detail = "Attempted C2 callback blocked by packet filter",
                    Severity = "MEDIUM",
                    Technique = "T1071",
                    TimestampUtc = DateTimeOffset.UtcNow
                }
            ],
            AttackerIps = ["198.51.100.25"],
            SuspiciousPersistenceItems = ["Registry autostart: evil.exe"],
            SecurityAlertIds = ["alert-12345"]
        };

        var json = ForensicEvidenceCollector.GenerateJsonBundle(bundle);
        Assert.False(string.IsNullOrWhiteSpace(json));

        var roundTrip = JsonConvert.DeserializeObject<ForensicEvidenceBundle>(json);
        Assert.NotNull(roundTrip);
        Assert.Equal(bundle.SchemaVersion, roundTrip.SchemaVersion);
        Assert.Equal(bundle.ChainOfCustody.Hostname, roundTrip.ChainOfCustody.Hostname);
        Assert.Equal(bundle.ChainOfCustody.EvidenceIntegritySha256, roundTrip.ChainOfCustody.EvidenceIntegritySha256);
        Assert.Single(roundTrip.Artifacts);
        Assert.Equal("Firewall Event", roundTrip.Artifacts[0].Category);
        Assert.Single(roundTrip.AttackerIps);
        Assert.Equal("198.51.100.25", roundTrip.AttackerIps[0]);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsExpectedSectionsAndIc3Guidance()
    {
        var coc = new ForensicChainOfCustody
        {
            Hostname = "FINANCE-PC01",
            OsDescription = "Windows 10 Pro",
            OsArchitecture = "X64",
            CollectorVersion = "Downpour Next v0.1.14",
            CollectedAtUtc = DateTimeOffset.UtcNow,
            LocalIpAddresses = "172.16.0.4",
            MacAddresses = "00:50:56:C0:00:01",
            EvidenceIntegritySha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        };

        var bundle = new ForensicEvidenceBundle
        {
            SchemaVersion = 1,
            ChainOfCustody = coc,
            Artifacts =
            [
                new()
                {
                    Category = "RDP Session",
                    Title = "Suspicious Remote Desktop Connection",
                    Detail = "Unauthorized session from unknown external gateway",
                    Severity = "HIGH",
                    Technique = "T1021.001",
                    TimestampUtc = DateTimeOffset.UtcNow
                }
            ],
            AttackerIps = ["185.220.101.5"],
            SuspiciousPersistenceItems = ["Scheduled task: SystemUpdateBackdoor"],
            SecurityAlertIds = []
        };

        var html = ForensicEvidenceCollector.GenerateHtmlReport(bundle);

        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("FINANCE-PC01", html);
        Assert.Contains("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", html);
        Assert.Contains("SHA-256 DIGITAL EVIDENCE SEAL", html);
        Assert.Contains("185.220.101.5", html);
        Assert.Contains("https://www.ic3.gov", html);
        Assert.Contains("FBI Internet Crime Complaint Center", html);
        Assert.Contains("Suspicious Remote Desktop Connection", html);
        Assert.Contains("T1021.001", html);
    }

    [Fact]
    public void GeneratePlainTextSummary_ContainsExpectedHeaders()
    {
        var coc = new ForensicChainOfCustody
        {
            Hostname = "LAPTOP-DEV",
            OsDescription = "Windows 11",
            OsArchitecture = "Arm64",
            CollectorVersion = "Downpour Next v0.1.14",
            CollectedAtUtc = DateTimeOffset.UtcNow,
            LocalIpAddresses = "192.168.0.12",
            MacAddresses = "12:34:56:78:9A:BC",
            EvidenceIntegritySha256 = "1234567890abcdef"
        };

        var bundle = new ForensicEvidenceBundle
        {
            SchemaVersion = 1,
            ChainOfCustody = coc,
            Artifacts =
            [
                new()
                {
                    Category = "Security Alert",
                    Title = "Sigma Match: Obfuscated PowerShell Command",
                    Detail = "powershell.exe -enc execution detected",
                    Severity = "CRITICAL",
                    Technique = "T1059.001",
                    TimestampUtc = DateTimeOffset.UtcNow
                }
            ],
            AttackerIps = [],
            SuspiciousPersistenceItems = [],
            SecurityAlertIds = ["alert-001"]
        };

        var summary = ForensicEvidenceCollector.GeneratePlainTextSummary(bundle);

        Assert.Contains("=== DOWNPOUR FORENSIC EVIDENCE REPORT ===", summary);
        Assert.Contains("=== DIGITAL CHAIN OF CUSTODY ===", summary);
        Assert.Contains("LAPTOP-DEV", summary);
        Assert.Contains("https://www.ic3.gov", summary);
        Assert.Contains("Sigma Match: Obfuscated PowerShell Command", summary);
    }
}
