using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatVerdictEngineTests
{
    private static (ThreatFeedDefinition, string) Hit(string id, string label = "x") => (ThreatFeedCatalog.Find(id)!, label);

    [Fact]
    public void OverlappingReputationListsDoNotManufactureConfidence()
    {
        var single = new ThreatEvidence(ThreatMatchPlaces.Dns, "example.test", [Hit("ipsum")], ConnectionObserved: true);
        var original = ThreatVerdictEngine.Assess(single);
        var combined = ThreatVerdictEngine.Assess(single with { Hits = [Hit("ipsum"), Hit("ipsum-5"), Hit("firehol-level1"), Hit("firehol-level2")] });
        Assert.Equal(original.Confidence, combined.Confidence);
        Assert.Equal(original.Verdict, combined.Verdict);
        Assert.Equal(ThreatVerdicts.Review, combined.Verdict);
        Assert.Contains(combined.Reasons, r => r.Contains("Independence is not established"));
        Assert.DoesNotContain(combined.Reasons, r => r.Contains("independent databases"));
    }

    [Fact]
    public void DuplicateListingIdsDoNotIncreaseConfidence()
    {
        var evidence = new ThreatEvidence(ThreatMatchPlaces.Connection, "203.0.113.1", [Hit("threatfox")]);
        Assert.Equal(ThreatVerdictEngine.Assess(evidence).Confidence,
            ThreatVerdictEngine.Assess(evidence with { Hits = [Hit("threatfox"), Hit("threatfox")] }).Confidence);
    }

    [Fact]
    public void ExactProgramHashKeepsItsValueWithoutAMultipleFeedBonus()
    {
        var evidence = new ThreatEvidence(ThreatMatchPlaces.Program, "hash", [Hit("malwarebazaar")], Signed: false);
        var original = ThreatVerdictEngine.Assess(evidence);
        var combined = ThreatVerdictEngine.Assess(evidence with { Hits = [Hit("malwarebazaar"), Hit("sigbase-hashes")] });
        Assert.Equal(ThreatVerdicts.Confirmed, combined.Verdict);
        Assert.Equal(original.Confidence, combined.Confidence);
    }

    [Fact]
    public void ObservedConnectionStillAddsEvidenceBeyondALookup()
    {
        var evidence = new ThreatEvidence(ThreatMatchPlaces.Dns, "example.test", [Hit("threatfox")], ConnectionObserved: false);
        Assert.True(ThreatVerdictEngine.Assess(evidence with { ConnectionObserved = true }).Confidence
            > ThreatVerdictEngine.Assess(evidence).Confidence);
    }

    [Fact]
    public void DnsLookupOnASinglePhishingListWithoutAConnectionIsOnlyLowPriorityReview()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Dns, "squarehigher.pgslot888x.com", [Hit("phishing-army")], ConnectionObserved: false));
        Assert.Equal(ThreatVerdicts.LikelyBenign, result.Verdict);
        Assert.Equal("LOW", result.Severity);
        Assert.Contains(result.Reasons, r => r.Contains("no connection", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DnsHitWithAConnectedNonBrowserAndTwoMalwareFeedsIsLikelyOrConfirmed()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Dns, "c2.example", [Hit("threatfox", "Malware C2 (AsyncRAT)"), Hit("urlhaus")],
            ConnectionObserved: true, ConnectedProgram: "updater.exe"));
        Assert.Contains(result.Verdict, new[] { ThreatVerdicts.Likely, ThreatVerdicts.Confirmed });
        Assert.Contains(result.Reasons, r => r.Contains("updater.exe"));
    }

    [Fact]
    public void BotnetConnectionFromUnknownProgramOnNonWebPortIsConfirmed()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Connection, "50.16.16.211", [Hit("feodo", "Botnet C2 (QakBot)"), Hit("threatfox")],
            "svch0st.exe", @"C:\Users\me\AppData\Roaming\svch0st.exe", RemotePort: 4444));
        Assert.Equal(ThreatVerdicts.Confirmed, result.Verdict);
        Assert.Contains(result.Severity, new[] { "HIGH", "CRITICAL" });
    }

    [Fact]
    public void BrowserTouchingASingleReputationListedAddressIsNotAThreat()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Connection, "1.2.3.4", [Hit("cins")], "msedge.exe", RemotePort: 443));
        Assert.Equal(ThreatVerdicts.LikelyBenign, result.Verdict);
        Assert.Equal("LOW", result.Severity);
    }

    [Fact]
    public void SignedVulnerableVendorDriverIsLegitimateButVulnerableNotMalware()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Driver, "hash", [Hit("loldrivers", "Vulnerable driver: AmdTools64.sys")],
            "AmdTools64.sys", @"C:\Windows\System32\drivers\AmdTools64.sys", Signed: true, Signer: "Advanced Micro Devices, Inc."));
        Assert.Equal(ThreatVerdicts.VulnerableLegitimate, result.Verdict);
        Assert.Equal("MEDIUM", result.Severity);
        Assert.Contains(result.Reasons, r => r.Contains("Advanced Micro Devices"));
    }

    [Fact]
    public void MaliciousDriverIsConfirmedCritical()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Driver, "hash", [Hit("loldrivers", "Malicious driver: poortry.sys")], Signed: true));
        Assert.Equal(ThreatVerdicts.Confirmed, result.Verdict);
        Assert.Equal("CRITICAL", result.Severity);
    }

    [Fact]
    public void ExactMalwareHashOnARunningProgramIsConfirmedCritical()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Program, "hash", [Hit("malwarebazaar")], "a.exe", @"C:\Users\me\Downloads\a.exe", Signed: false));
        Assert.Equal(ThreatVerdicts.Confirmed, result.Verdict);
        Assert.Equal("CRITICAL", result.Severity);
    }

    [Fact]
    public void NamesSinkholedByTheHostsFileAreAlreadyBlockedNotThreats()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Dns, "dl.natgo.cn", [Hit("urlhaus"), Hit("threatfox")], Sinkholed: true));
        Assert.Equal(ThreatVerdicts.Blocked, result.Verdict);
        Assert.Equal("LOW", result.Severity);
        Assert.True(ThreatVerdicts.IsCleared(result.Verdict));
    }

    [Fact]
    public void EveryAssessmentExplainsItself()
    {
        var result = ThreatVerdictEngine.Assess(new ThreatEvidence(ThreatMatchPlaces.Connection, "185.220.101.4", [Hit("tor-exit")], "tor.exe"));
        Assert.NotEmpty(result.Reasons);
        Assert.InRange(result.Confidence, 1, 99);
    }

    private static FirewallRuleEntry Rule(string name, string ports, string remote = "*", string app = "", string service = "", string grouping = "") =>
        new(name, "Inbound", "Allow", true, "TCP", ports, remote, "Domain, Private, Public", app, service, "", grouping, false);

    [Fact]
    public void BuiltInWindowsAndLocalOnlyFirewallRulesAreLowPriority()
    {
        var findings = FirewallRuleAnalyzer.Analyze("Running", [], [
            Rule("Remote Assistance (DCOM-In)", "135", app: @"%SystemRoot%\System32\svchost.exe", grouping: "@FirewallAPI.dll,-33002"),
            Rule("HNS Container Networking - DNS (UDP-In) - X - 0", "53", remote: "172.20.16.0/20"),
            Rule("Third-party remote tool", "3389", app: @"C:\Tools\remote.exe"),
        ]);
        Assert.Equal("LOW", findings.Single(f => f.Indicator.StartsWith("Remote Assistance")).Severity);
        Assert.Equal("LOW", findings.Single(f => f.Indicator.StartsWith("HNS")).Severity);
        Assert.Contains("local network only", findings.Single(f => f.Indicator.StartsWith("HNS")).Summary);
        Assert.Equal("MEDIUM", findings.Single(f => f.Indicator.StartsWith("Third-party")).Severity);
    }

    [Theory]
    [InlineData("LocalSubnet", true)]
    [InlineData("10.0.0.0/8,192.168.1.0/24", true)]
    [InlineData("*", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("", false)]
    public void LocalOnlyScopeDetection(string remote, bool expected) => Assert.Equal(expected, FirewallRuleAnalyzer.IsLocalNetworkOnly(remote));
}
