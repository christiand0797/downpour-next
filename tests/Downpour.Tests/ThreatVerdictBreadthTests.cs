using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatVerdictBreadthTests
{
    private static (ThreatFeedDefinition Feed, string Label) Hit(string id, string? label = null)
    {
        var feed = ThreatFeedCatalog.Find(id) ?? throw new InvalidOperationException(id);
        return (feed, label ?? feed.DefaultLabel);
    }

    [Theory]
    [InlineData("blp-phishing")]
    [InlineData("blp-fraud")]
    [InlineData("phishing-db-domain")]
    public void NewPhishingReportsUsePhishingEvidenceWithoutTreatingALookupAsProof(string id)
    {
        var evidence = new ThreatEvidence(ThreatMatchPlaces.Dns, "example.test", [Hit(id)], ConnectionObserved: false);
        var lookup = ThreatVerdictEngine.Assess(evidence);
        var connected = ThreatVerdictEngine.Assess(evidence with { ConnectionObserved = true });

        Assert.Equal(ThreatVerdicts.LikelyBenign, lookup.Verdict);
        Assert.Equal(ThreatVerdicts.Likely, connected.Verdict);
        Assert.Contains(lookup.Reasons, r => r.Contains("phishing or fraud"));
        Assert.DoesNotContain(connected.Reasons, r => r.Contains("informational list"));
    }

    [Theory]
    [InlineData("threatview-ip")]
    [InlineData("threatview-domain")]
    [InlineData("phishing-db-ip")]
    public void BroadReputationMatchesStayContextualWhenAConnectionIsObserved(string id)
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Connection, "203.0.113.3", [Hit(id)], "updater.exe", RemotePort: 443));

        Assert.Equal(ThreatVerdicts.Review, result.Verdict);
        Assert.Contains(result.Reasons, r => r.Contains("shared, recycled or misclassified"));
        Assert.DoesNotContain(result.Reasons, r => r.Contains("informational list"));
    }

    [Fact]
    public void UrlHostReportDoesNotImplyTheReportedPathWasVisitedOrFtpIsCommandAndControl()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Connection, "203.0.113.3", [Hit("threatview-url")], "ftp.exe", RemotePort: 21));

        Assert.Equal(ThreatVerdicts.Review, result.Verdict);
        Assert.Contains(result.Reasons, r => r.Contains("URL path was not observed"));
        Assert.DoesNotContain(result.Reasons, r => r.Contains("informational list") || r.Contains("typical of command-and-control"));
    }

    [Theory]
    [InlineData("threatview-md5")]
    [InlineData("threatview-sha")]
    [InlineData("digitalside-hash")]
    [InlineData("malwarebazaar")]
    public void SignedGenericHashMatchDoesNotInventALolDriversVulnerability(string id)
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Driver, "hash", [Hit(id)], Signed: true, Signer: "Example Publisher"));

        Assert.Equal(ThreatVerdicts.Likely, result.Verdict);
        Assert.Equal("HIGH", result.Severity);
        Assert.Contains(result.Reasons, r => r.Contains("file fingerprint"));
        Assert.Contains(result.Reasons, r => r.Contains("Example Publisher"));
        Assert.DoesNotContain(result.Reasons, r => r.Contains("LOLDrivers") || r.Contains("not malware"));
    }

    [Theory]
    [InlineData("threatview-md5")]
    [InlineData("threatview-sha")]
    [InlineData("digitalside-hash")]
    public void UnknownDriverSignatureStaysUnknownRatherThanTreatingItAsUnsigned(string id)
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Driver, "hash", [Hit(id)], Signed: null));

        Assert.Equal(ThreatVerdicts.Likely, result.Verdict);
        Assert.Contains(result.Reasons, r => r == "The signature could not be checked.");
        Assert.DoesNotContain(result.Reasons, r => r == "The driver file is not validly signed.");
    }

    [Fact]
    public void VulnerableDriverListingCannotOverrideAnotherMalwareHashReport()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Driver, "hash",
            [Hit("loldrivers", "Vulnerable driver: example.sys"), Hit("threatview-sha")], Signed: true));

        Assert.Equal(ThreatVerdicts.Likely, result.Verdict);
        Assert.Contains(result.Reasons, r => r.Contains("does not dismiss evidence"));
        Assert.DoesNotContain(result.Reasons, r => r.Contains("not malware"));
    }

    [Fact]
    public void AnotherFeedCannotImpersonateLolDriversWithItsLabel()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Driver, "hash",
            [Hit("threatview-sha", "Malicious driver: example.sys")], Signed: true));

        Assert.Equal(ThreatVerdicts.Likely, result.Verdict);
        Assert.DoesNotContain(result.Reasons, r => r.Contains("LOLDrivers classifies"));
    }

    [Fact]
    public void HistoricalHashMatchExplainsArchiveProvenance()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Driver, "hash", [Hit("digitalside-hash")], Signed: false));

        Assert.Contains(result.Reasons, r => r.Contains("archive match is not a new sighting"));
    }
}
