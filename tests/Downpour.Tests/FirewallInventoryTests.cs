using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class FirewallInventoryTests
{
    private static FirewallRuleEntry Rule(string name = "Rule", string direction = "Inbound", string action = "Allow", bool enabled = true,
        string ports = "", string application = "", string protocol = "TCP", string service = "", string package = "") =>
        new(name, direction, action, enabled, protocol, ports, "*", "All", application, service, package, "", FirewallRuleAnalyzer.IsDownpourRule(name));

    private static readonly FirewallProfileState[] AllOn =
    [
        new("Domain", false, true, "Block", "Allow"),
        new("Private", true, true, "Block", "Allow"),
        new("Public", false, true, "Block", "Allow"),
    ];

    [Theory]
    [InlineData("445", new[] { 445 })]
    [InlineData("4450", new int[0])]
    [InlineData("3389, 80", new[] { 3389 })]
    [InlineData("5900-5986", new[] { 5900, 5985, 5986 })]
    [InlineData("9000-8000", new int[0])]
    [InlineData("RPC", new int[0])]
    [InlineData("", new int[0])]
    public void SuspiciousPortsUseExactAndRangeMatching(string ports, int[] expected) =>
        Assert.Equal(expected, FirewallRuleAnalyzer.SuspiciousPortsIn(ports));

    [Fact]
    public void SuspiciousPortListMatchesV29()
    {
        // firewall_tamper_detector.py SUSPICIOUS_ALLOW_PORTS (28 ports).
        Assert.Equal(28, FirewallRuleAnalyzer.SuspiciousAllowPorts.Count);
        Assert.Contains(4444, FirewallRuleAnalyzer.SuspiciousAllowPorts);
        Assert.Contains(9050, FirewallRuleAnalyzer.SuspiciousAllowPorts);
        Assert.Equal(28, FirewallRuleAnalyzer.SuspiciousPortsIn("*").Count);
    }

    [Theory]
    [InlineData("downpour_block_1.2.3.4", true)]
    [InlineData("DownpourC2Block", true)]
    [InlineData("Core Networking - downpour", false)]
    public void DownpourRulesUseV29Prefix(string name, bool expected) =>
        Assert.Equal(expected, FirewallRuleAnalyzer.IsDownpourRule(name));

    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\x.exe", true)]
    [InlineData(@"C:\Users\a\Downloads\tool.exe", true)]
    [InlineData(@"C:\Users\Public\x.exe", true)]
    [InlineData(@"%TEMP%\x.exe", true)]
    [InlineData(@"C:\Users\a\AppData\Local\Google\Chrome\Application\chrome.exe", false)]
    [InlineData(@"C:\Program Files\App\app.exe", false)]
    [InlineData(@"%SystemRoot%\system32\svchost.exe", false)]
    [InlineData("", false)]
    public void StagingProgramPaths(string path, bool expected) =>
        Assert.Equal(expected, FirewallRuleAnalyzer.IsStagingPath(path));

    [Fact]
    public void AnalyzeReportsServiceProfileAndRuleFindings()
    {
        var profiles = new[] { AllOn[0], AllOn[1] with { Enabled = false }, AllOn[2] with { Enabled = false } };
        var rules = new[]
        {
            Rule("Open RDP", ports: "3389"),
            Rule("Open RDP", ports: "3389", protocol: "UDP"),
            Rule("Disabled SMB", ports: "445", enabled: false),
            Rule("Outbound", direction: "Outbound", ports: "445"),
            Rule("Block SSH", action: "Block", ports: "22"),
            Rule("Dropper", ports: "8000", application: @"C:\Users\a\Downloads\x.exe"),
        };

        var findings = FirewallRuleAnalyzer.Analyze("Stopped", profiles, rules);

        Assert.Contains(findings, f => f.Severity == "CRITICAL" && f.Indicator == "MpsSvc:Stopped");
        Assert.Contains(findings, f => f.Severity == "CRITICAL" && f.Indicator == "Private:Off");
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Indicator == "Public:Off");
        Assert.Single(findings, f => f.Severity == "MEDIUM" && f.Summary.Contains("Open RDP"));
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Summary.Contains("Dropper"));
        Assert.DoesNotContain(findings, f => f.Summary.Contains("Disabled SMB") || f.Summary.Contains("Outbound") || f.Summary.Contains("Block SSH"));
        Assert.All(findings, f => Assert.Equal("T1562.004", f.Technique));
    }

    [Fact]
    public void ProgramScopedAnyPortRulesAreNormalButUnscopedOnesAreFlagged()
    {
        var findings = FirewallRuleAnalyzer.Analyze("Running", AllOn,
        [
            Rule("chrome.exe", ports: "*", application: @"C:\Users\a\AppData\Local\Google\Chrome\Application\chrome.exe"),
            Rule("Svc any", ports: "*", service: "Dnscache"),
            Rule("Store app", ports: "", package: "S-1-15-2-1"),
            Rule("ICMP echo", ports: "", protocol: "ICMPv4"),
            Rule("Wide open", ports: "*"),
            Rule("Wide open", ports: "*", protocol: "UDP"),
        ]);

        var single = Assert.Single(findings);
        Assert.Equal("HIGH", single.Severity);
        Assert.Contains("every port", single.Summary);
    }

    [Fact]
    public void AnalyzeIsQuietForHealthyState()
    {
        Assert.Empty(FirewallRuleAnalyzer.Analyze("Running", AllOn, [Rule("Web", ports: "80,443")]));
        // An unknown service state or profile is not a finding.
        Assert.Empty(FirewallRuleAnalyzer.Analyze("Unknown", [AllOn[0] with { Enabled = null }], []));
    }

    [Fact]
    public void RuleStoreEntriesYieldPackageScopeOnlyWhenComplete()
    {
        Assert.Equal(("Inbound", "Xbox", "Microsoft.GamingApp_8wekyb3d8bbwe"),
            FirewallInventoryProvider.ParseRuleStoreEntry("v2.33|Action=Allow|Active=TRUE|Dir=In|Name=Xbox|Desc=Xbox|PFN=Microsoft.GamingApp_8wekyb3d8bbwe|Edge=TRUE|"));
        Assert.Null(FirewallInventoryProvider.ParseRuleStoreEntry(@"v2.33|Action=Allow|Dir=In|Name=Core|App=C:\x.exe|"));
        Assert.Null(FirewallInventoryProvider.ParseRuleStoreEntry("v2.33|Dir=Sideways|Name=X|PFN=P|"));
        Assert.Null(FirewallInventoryProvider.ParseRuleStoreEntry("garbage"));
    }

    [Theory]
    [InlineData(7, "All")]
    [InlineData(int.MaxValue, "All")]
    [InlineData(2, "Private")]
    [InlineData(5, "Domain, Public")]
    [InlineData(0, "None")]
    public void ProfileMaskMapping(int mask, string expected) =>
        Assert.Equal(expected, FirewallInventoryProvider.MapProfiles(mask));

    [Fact]
    public void ActionAndProtocolMapping()
    {
        Assert.Equal("Block", FirewallInventoryProvider.MapAction(0));
        Assert.Equal("Allow", FirewallInventoryProvider.MapAction(1));
        Assert.Equal("Unknown", FirewallInventoryProvider.MapAction(9));
        Assert.Equal("TCP", FirewallInventoryProvider.MapProtocol(6));
        Assert.Equal("Any", FirewallInventoryProvider.MapProtocol(256));
        Assert.Equal("47", FirewallInventoryProvider.MapProtocol(47));
    }

    [Fact]
    public void LiveCaptureIsValidAndFitsThePipeBound()
    {
        var snapshot = new FirewallInventoryProvider(new WindowsServiceInventoryProvider()).Capture();

        Assert.True(FirewallInventoryClient.IsValid(snapshot));
        Assert.Equal(3, snapshot.Profiles.Count);
        Assert.True(snapshot.RuleCount > 0, string.Join(" ", snapshot.Warnings));
        Assert.Contains(snapshot.Profiles, profile => profile.IsActive);
        Assert.All(snapshot.Profiles, profile => Assert.NotNull(profile.Enabled));
        Assert.All(snapshot.Profiles, profile => Assert.NotEqual("Unknown", profile.DefaultInboundAction));
        Assert.NotEqual("Unknown", snapshot.ServiceState);
        var payload = JsonSerializer.SerializeToUtf8Bytes(snapshot, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.True(payload.Length < BoundedJson.MaximumPayloadBytes, $"Payload {payload.Length:N0} bytes for {snapshot.Rules.Count} rules.");
        Assert.True(FirewallInventoryClient.IsValid(BoundedJson.Deserialize<FirewallSnapshot>(payload)));
    }

    [Fact]
    public void ClientRejectsUnknownStatusesAndSeverities()
    {
        var good = new FirewallSnapshot(1, DateTimeOffset.UtcNow, "Running", AllOn, 1, [Rule()], FirewallBlockedEventsStatuses.NoEvents, [], [], []);
        Assert.True(FirewallInventoryClient.IsValid(good));
        Assert.False(FirewallInventoryClient.IsValid(good with { BlockedEventsStatus = "Maybe" }));
        Assert.False(FirewallInventoryClient.IsValid(good with { RuleCount = 0 }));
        Assert.False(FirewallInventoryClient.IsValid(good with { Findings = [new("SEVERE", "T", "s", "i")] }));
        Assert.False(FirewallInventoryClient.IsValid(good with { Profiles = [.. AllOn, AllOn[0]] }));
    }
}
