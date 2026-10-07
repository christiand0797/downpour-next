using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class DnsInventoryTests
{
    [Fact]
    public void ShannonEntropy_CalculatesExpectedEntropy()
    {
        Assert.Equal(0.0, DgaDetector.ShannonEntropy(""), 2);
        Assert.Equal(0.0, DgaDetector.ShannonEntropy("aaaaaa"), 2);

        // 2 distinct characters equal frequency -> 1.0 bit
        Assert.Equal(1.0, DgaDetector.ShannonEntropy("abababab"), 2);

        // High entropy random string
        var entropy = DgaDetector.ShannonEntropy("abcdefghijklmnop");
        Assert.True(entropy >= 3.9);
    }

    [Fact]
    public void ConsonantAndDigitRatios_CalculateCorrectly()
    {
        Assert.Equal(0.0, DgaDetector.ConsonantRatio("aeiou"));
        Assert.Equal(1.0, DgaDetector.ConsonantRatio("bcdfghjklmnpqrstvwxyz"));
        Assert.Equal(0.5, DgaDetector.ConsonantRatio("ab"));

        Assert.Equal(0.5, DgaDetector.DigitRatio("abc123"));
        Assert.Equal(0.0, DgaDetector.DigitRatio("nodigits"));
        Assert.Equal(1.0, DgaDetector.DigitRatio("123456"));
    }

    [Fact]
    public void ScoreDomain_WhitelistedDomainsAreClean()
    {
        var result = DgaDetector.ScoreDomain("login.microsoftonline.com");
        Assert.Equal(0, result.Score);
        Assert.False(result.IsDga);
        Assert.Contains(result.Factors, f => f.Contains("known-good suffix"));

        var googleResult = DgaDetector.ScoreDomain("www.google.com");
        Assert.Equal(0, googleResult.Score);
        Assert.False(googleResult.IsDga);
    }

    [Fact]
    public void ScoreDomain_BenignDomainsHaveLowScores()
    {
        var result = DgaDetector.ScoreDomain("apple.com");
        Assert.False(result.IsDga);
        Assert.True(result.Score < 50);

        var result2 = DgaDetector.ScoreDomain("stackoverflow.com");
        Assert.False(result2.IsDga);
        Assert.True(result2.Score < 50);
    }

    [Fact]
    public void ScoreDomain_ObviousDgaDomainScoresHigh()
    {
        // High entropy, high consonant ratio, unusual bigrams on risky TLD
        var result = DgaDetector.ScoreDomain("xkqzwvjbmrfptyldn.top");
        Assert.True(result.IsDga, $"Expected DGA for high-entropy domain, but score was {result.Score}: {string.Join("; ", result.Factors)}");
        Assert.True(result.Score >= 70);
    }

    [Fact]
    public void ScoreDomain_ShortDomainsAreNotDga()
    {
        var result = DgaDetector.ScoreDomain("a.co");
        Assert.False(result.IsDga);
        Assert.Equal(0, result.Score);
        Assert.Contains(result.Factors, f => f.Contains("benign characteristics"));
    }

    [Fact]
    public void EvaluateSpf_ParsesValidAndPermissiveRecords()
    {
        var (status, verdict, record) = EmailSecurityAnalyzer.EvaluateSpf(["v=spf1 include:_spf.google.com ~all"]);
        Assert.Equal("WARN", status);
        Assert.Contains("softfail", verdict, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("v=spf1", record);

        var (strictStatus, strictVerdict, _) = EmailSecurityAnalyzer.EvaluateSpf(["v=spf1 -all"]);
        Assert.Equal("OK", strictStatus);
        Assert.Contains("hard fail", strictVerdict, StringComparison.OrdinalIgnoreCase);

        var (insecureStatus, insecureVerdict, _) = EmailSecurityAnalyzer.EvaluateSpf(["v=spf1 +all"]);
        Assert.Equal("HIGH", insecureStatus);
        Assert.Contains("+all", insecureVerdict);

        var (missingStatus, missingVerdict, _) = EmailSecurityAnalyzer.EvaluateSpf([]);
        Assert.Equal("HIGH", missingStatus);
        Assert.Contains("No SPF record found", missingVerdict);
    }

    [Fact]
    public void EvaluateDmarc_ParsesPolicyCorrectly()
    {
        var (rejectStatus, rejectVerdict, rejectRecord) = EmailSecurityAnalyzer.EvaluateDmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]);
        Assert.Equal("OK", rejectStatus);
        Assert.Contains("p=reject", rejectVerdict);
        Assert.Contains("p=reject", rejectRecord);

        var (quarantineStatus, quarantineVerdict, _) = EmailSecurityAnalyzer.EvaluateDmarc(["v=DMARC1; p=quarantine;"]);
        Assert.Equal("WARN", quarantineStatus);
        Assert.Contains("p=quarantine", quarantineVerdict);

        var (noneStatus, noneVerdict, _) = EmailSecurityAnalyzer.EvaluateDmarc(["v=DMARC1; p=none;"]);
        Assert.Equal("HIGH", noneStatus);
        Assert.Contains("p=none", noneVerdict);

        var (missingStatus, missingVerdict, _) = EmailSecurityAnalyzer.EvaluateDmarc([]);
        Assert.Equal("HIGH", missingStatus);
        Assert.Contains("No DMARC record found", missingVerdict);
    }

    [Fact]
    public void DnsInventoryClient_ValidatesSnapshots()
    {
        var validSnapshot = new DnsCacheSnapshot(
            1,
            DateTimeOffset.UtcNow,
            1,
            0,
            0,
            [new DnsCacheEntry("example.com", 1, 15, false, ["Benign domain"])],
            [],
            []
        );

        Assert.True(DnsInventoryClient.IsValid(validSnapshot));

        // Invalid schema version
        var wrongSchemaSnapshot = validSnapshot with { SchemaVersion = 2 };
        Assert.False(DnsInventoryClient.IsValid(wrongSchemaSnapshot));

        // Bounded list check (over 4096 entries)
        var excessiveEntries = Enumerable.Range(0, 4097)
            .Select(i => new DnsCacheEntry($"domain{i}.com", 1, 10, false, ["Test"]))
            .ToList();
        var oversizedSnapshot = validSnapshot with { Entries = excessiveEntries };
        Assert.False(DnsInventoryClient.IsValid(oversizedSnapshot));

        // Invalid severity
        var badFinding = new DnsFinding("INVALID_SEVERITY", "T1568", "Summary", "indicator");
        var badFindingSnapshot = validSnapshot with { Findings = [badFinding] };
        Assert.False(DnsInventoryClient.IsValid(badFindingSnapshot));
    }

    [Fact]
    public void DnsInventoryProvider_Capture_ExecutesCleanly()
    {
        var tempBaseline = Path.Combine(Path.GetTempPath(), $"downpour-dns-test-{Guid.NewGuid()}.json");
        try
        {
            var provider = new DnsInventoryProvider(tempBaseline);
            var snapshot = provider.Capture();

            Assert.NotNull(snapshot);
            Assert.True(snapshot.CapturedAtUtc <= DateTimeOffset.UtcNow);
            Assert.True(snapshot.TotalEntries >= 0);
            Assert.NotNull(snapshot.Entries);
            Assert.NotNull(snapshot.Findings);

            // Verify baseline file was created
            Assert.True(File.Exists(tempBaseline));
            var content = File.ReadAllText(tempBaseline);
            Assert.False(string.IsNullOrWhiteSpace(content));
        }
        finally
        {
            if (File.Exists(tempBaseline)) File.Delete(tempBaseline);
        }
    }
}
