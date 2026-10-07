using System.Net;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Xunit;

namespace Downpour.Tests;

public sealed class InMemoryFirewallPolicyBackend : IFirewallPolicyBackend
{
    private readonly Dictionary<string, FirewallRuleSummary> _rules = new(StringComparer.OrdinalIgnoreCase);

    public void AddRule(string name, string description, int action, int direction, bool enabled, string remoteAddresses, int profiles, string grouping)
    {
        _rules[name] = new FirewallRuleSummary(
            Name: name,
            Description: description,
            RemoteAddresses: remoteAddresses,
            Direction: direction == 1 ? "Inbound" : "Outbound",
            Action: action == 0 ? "Block" : "Allow",
            Enabled: enabled);
    }

    public void RemoveRule(string name)
    {
        _rules.Remove(name);
    }

    public IReadOnlyList<FirewallRuleSummary> EnumerateRules() => _rules.Values.ToList();

    public bool HasRule(string name) => _rules.ContainsKey(name);
    public int Count => _rules.Count;
}

public sealed class FirewallActionTests : IDisposable
{
    private readonly string _testStateDir;
    private readonly string _auditLogPath;
    private readonly ActionAuditLog _auditLog;
    private readonly ActionConsentStore _consentStore;
    private readonly SensorSettingsStore _settingsStore;
    private readonly InMemoryFirewallPolicyBackend _backend;
    private readonly FirewallActionExecutor _executor;
    private readonly FirewallActionHandler _handler;

    public FirewallActionTests()
    {
        _testStateDir = Path.Combine(Path.GetTempPath(), "downpour_test_fwaction_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testStateDir);
        _auditLogPath = Path.Combine(_testStateDir, "test-audit.v1.jsonl");
        _auditLog = new ActionAuditLog(_auditLogPath);
        _consentStore = new ActionConsentStore();

        var settingsPath = Path.Combine(_testStateDir, "sensor-settings.v1.json");
        _settingsStore = new SensorSettingsStore(settingsPath);

        _backend = new InMemoryFirewallPolicyBackend();
        _executor = new FirewallActionExecutor(_backend);
        _handler = new FirewallActionHandler(_executor, _settingsStore, _consentStore, _auditLog);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testStateDir))
                Directory.Delete(_testStateDir, recursive: true);
        }
        catch { }
    }

    [Theory]
    [InlineData("203.0.113.1", true)]
    [InlineData("198.51.100.25", true)]
    [InlineData("2001:db8::1", true)]
    [InlineData("127.0.0.1", false)] // Loopback
    [InlineData("::1", false)] // IPv6 loopback
    [InlineData("0.0.0.0", false)] // Any
    [InlineData("::", false)] // IPv6 Any
    [InlineData("255.255.255.255", false)] // Broadcast
    [InlineData("169.254.10.5", false)] // Link-local
    [InlineData("224.0.0.1", false)] // Multicast
    [InlineData("239.255.255.250", false)] // Multicast
    [InlineData("not-an-ip", false)] // Invalid
    [InlineData("", false)] // Empty
    public void ValidateRemoteIp_EnforcesStrictSecurityPolicy(string ip, bool shouldBeAllowed)
    {
        var (allowed, denyReason, parsedIp) = _executor.ValidateRemoteIp(ip);
        if (shouldBeAllowed)
        {
            Assert.True(allowed);
            Assert.Null(denyReason);
            Assert.NotNull(parsedIp);
        }
        else
        {
            Assert.False(allowed);
            Assert.NotNull(denyReason);
            Assert.Null(parsedIp);
        }
    }

    [Theory]
    [InlineData("DownpourNext_Block_198.51.100.1_Out", true)]
    [InlineData("downpour_c2_block", true)]
    [InlineData("DOWNPOUR_PORT_4444", true)]
    [InlineData("Core Networking - DNS (UDP-Out)", false)]
    [InlineData("Windows Defender Firewall Remote Management", false)]
    [InlineData("Google Chrome", false)]
    [InlineData("", false)]
    public void ValidateRuleNameForRemoval_ProtectsNonDownpourRules(string ruleName, bool shouldBeAllowed)
    {
        var (allowed, denyReason) = _executor.ValidateRuleNameForRemoval(ruleName);
        if (shouldBeAllowed)
        {
            Assert.True(allowed);
            Assert.Null(denyReason);
        }
        else
        {
            Assert.False(allowed);
            Assert.NotNull(denyReason);
        }
    }

    [Fact]
    public void BlockRemoteIp_CreatesInboundAndOutboundRules()
    {
        var ip = IPAddress.Parse("198.51.100.42");
        var (succeeded, createdRules, error) = _executor.BlockRemoteIp(ip, durationMinutes: 60, reason: "Test block");

        Assert.True(succeeded);
        Assert.Null(error);
        Assert.Equal(2, createdRules.Count);
        Assert.Contains("DownpourNext_Block_198.51.100.42_Out", createdRules);
        Assert.Contains("DownpourNext_Block_198.51.100.42_In", createdRules);

        Assert.True(_backend.HasRule("DownpourNext_Block_198.51.100.42_Out"));
        Assert.True(_backend.HasRule("DownpourNext_Block_198.51.100.42_In"));
    }

    [Fact]
    public void CleanupLegacyRules_RemovesOnlyLegacyRules()
    {
        _backend.AddRule("DOWNPOUR_PORT_22", "v29 ssh block", 0, 1, true, "*", 7, "Downpour");
        _backend.AddRule("downpour_c2_rule", "v29 c2 block", 0, 2, true, "*", 7, "Downpour");
        _backend.AddRule("DownpourNext_Block_198.51.100.1_Out", "Next rule", 0, 2, true, "198.51.100.1", 7, "Downpour Next");
        _backend.AddRule("Windows_Defender_Rule", "System rule", 0, 1, true, "*", 7, "System");

        var (succeeded, removedRules, error) = _executor.CleanupLegacyRules();

        Assert.True(succeeded);
        Assert.Null(error);
        Assert.Equal(2, removedRules.Count);
        Assert.Contains("DOWNPOUR_PORT_22", removedRules);
        Assert.Contains("downpour_c2_rule", removedRules);

        // Confirm legacy removed, but Next rule and system rule preserved
        Assert.False(_backend.HasRule("DOWNPOUR_PORT_22"));
        Assert.False(_backend.HasRule("downpour_c2_rule"));
        Assert.True(_backend.HasRule("DownpourNext_Block_198.51.100.1_Out"));
        Assert.True(_backend.HasRule("Windows_Defender_Rule"));
    }

    [Fact]
    public void CleanupExpiredRules_RemovesExpiredRulesOnly()
    {
        var expiredTime = DateTimeOffset.UtcNow.AddMinutes(-10).ToString("O");
        var futureTime = DateTimeOffset.UtcNow.AddMinutes(60).ToString("O");

        _backend.AddRule("DownpourNext_Block_1_Out", $"Expiry: {expiredTime}", 0, 2, true, "1.1.1.1", 7, "Downpour Next");
        _backend.AddRule("DownpourNext_Block_2_Out", $"Expiry: {futureTime}", 0, 2, true, "2.2.2.2", 7, "Downpour Next");
        _backend.AddRule("DownpourNext_Block_3_Out", "Expiry: Permanent", 0, 2, true, "3.3.3.3", 7, "Downpour Next");

        var removed = _executor.CleanupExpiredRules();

        Assert.Single(removed);
        Assert.Equal("DownpourNext_Block_1_Out", removed[0]);

        Assert.False(_backend.HasRule("DownpourNext_Block_1_Out"));
        Assert.True(_backend.HasRule("DownpourNext_Block_2_Out"));
        Assert.True(_backend.HasRule("DownpourNext_Block_3_Out"));
    }

    [Fact]
    public async Task ConsentIsBoundToTheReviewedDuration()
    {
        var preview = await _handler.HandleAsync(new FirewallActionRequest(1, Guid.NewGuid(), FirewallActionOperations.PreviewBlockIp,
            TargetIp: "198.51.100.7", DurationMinutes: 60), callerDenial: null, CancellationToken.None);
        Assert.True(preview.Accepted);

        // Reusing the confirmation for a longer block must fail.
        var longer = await _handler.HandleAsync(new FirewallActionRequest(1, Guid.NewGuid(), FirewallActionOperations.BlockIp,
            TargetIp: "198.51.100.7", DurationMinutes: 10080, ConsentToken: preview.Preview!.ConsentToken), callerDenial: null, CancellationToken.None);
        Assert.Equal("denied-consent", longer.ResultCode);
        Assert.False(_backend.HasRule("DownpourNext_Block_198.51.100.7_Out"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(FirewallActionExecutor.MaximumBlockMinutes + 1)]
    public void BlocksMustExpire(int minutes)
    {
        var (succeeded, created, _) = _executor.BlockRemoteIp(IPAddress.Parse("198.51.100.8"), minutes, null);
        Assert.False(succeeded);
        Assert.Empty(created);
        Assert.Null(FirewallActionPipeWorker.ParseStrictRequest(System.Text.Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"block-ip\",\"targetIp\":\"198.51.100.8\",\"durationMinutes\":" + minutes + "}")));
    }

    [Fact]
    public void ReasonTextCannotSpoofTheExpiry()
    {
        var (succeeded, _, _) = _executor.BlockRemoteIp(IPAddress.Parse("198.51.100.9"), 60, "x | Expiry: 2000-01-01T00:00:00Z");
        Assert.True(succeeded);
        Assert.Empty(_executor.CleanupExpiredRules());
        Assert.True(_backend.HasRule("DownpourNext_Block_198.51.100.9_Out"));
    }

    [Fact]
    public async Task HandleAsync_RejectsDeniedCaller()
    {
        var request = new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.PreviewBlockIp,
            TargetIp: "198.51.100.1");

        var response = await _handler.HandleAsync(request, callerDenial: "Caller not Downpour Desktop", CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("denied-caller", response.ResultCode);
    }

    [Fact]
    public async Task HandleAsync_RejectsWhenFeatureSwitchIsDisabled()
    {
        _settingsStore.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.FirewallActions, false));

        var request = new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.PreviewBlockIp,
            TargetIp: "198.51.100.1");

        var response = await _handler.HandleAsync(request, callerDenial: null, CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("disabled", response.ResultCode);
    }

    [Fact]
    public async Task HandleAsync_PreviewAndBlockIp_ExecutesWithValidConsent()
    {
        var targetIp = "198.51.100.99";

        // Step 1: Preview request
        var previewRequest = new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.PreviewBlockIp,
            TargetIp: targetIp,
            DurationMinutes: 120,
            Reason: "Suspicious egress beaconing");

        var previewResponse = await _handler.HandleAsync(previewRequest, callerDenial: null, CancellationToken.None);

        Assert.True(previewResponse.Accepted);
        Assert.Equal("preview", previewResponse.ResultCode);
        Assert.NotNull(previewResponse.Preview);
        Assert.NotNull(previewResponse.Preview.ConsentToken);
        Assert.Equal(2, previewResponse.Preview.RulesAffected.Count);

        var consentToken = previewResponse.Preview.ConsentToken;

        // Step 2: Attempt execute with invalid token -> rejected
        var invalidExecuteRequest = new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.BlockIp,
            TargetIp: targetIp,
            DurationMinutes: 120,
            ConsentToken: "invalid-token");

        var invalidResponse = await _handler.HandleAsync(invalidExecuteRequest, callerDenial: null, CancellationToken.None);
        Assert.False(invalidResponse.Accepted);
        Assert.Equal("denied-consent", invalidResponse.ResultCode);

        // Step 3: Attempt execute with valid token -> success
        var validExecuteRequest = new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.BlockIp,
            TargetIp: targetIp,
            DurationMinutes: 120,
            ConsentToken: consentToken);

        var validResponse = await _handler.HandleAsync(validExecuteRequest, callerDenial: null, CancellationToken.None);
        Assert.True(validResponse.Accepted);
        Assert.Equal("blocked", validResponse.ResultCode);
        Assert.Equal(2, validResponse.RulesModified?.Count);

        // Verify rules in backend
        Assert.True(_backend.HasRule("DownpourNext_Block_198.51.100.99_Out"));
        Assert.True(_backend.HasRule("DownpourNext_Block_198.51.100.99_In"));

        // Verify audit log has entries
        var auditLines = _auditLog.ReadRecent(10);
        Assert.Contains(auditLines, l => l.Contains("preview-block-ip"));
        Assert.Contains(auditLines, l => l.Contains("block-ip") && l.Contains("blocked"));
    }

    [Fact]
    public async Task HandleAsync_PreviewAndRemoveRule_ExecutesWithConsent()
    {
        var ruleName = "DownpourNext_Block_198.51.100.5_Out";
        _backend.AddRule(ruleName, "test", 0, 2, true, "198.51.100.5", 7, "Downpour Next");

        // Preview
        var previewReq = new FirewallActionRequest(1, Guid.NewGuid(), FirewallActionOperations.PreviewRemoveRule, RuleName: ruleName);
        var previewResp = await _handler.HandleAsync(previewReq, callerDenial: null, CancellationToken.None);

        Assert.True(previewResp.Accepted);
        Assert.NotNull(previewResp.Preview?.ConsentToken);

        // Remove
        var removeReq = new FirewallActionRequest(1, Guid.NewGuid(), FirewallActionOperations.RemoveRule, RuleName: ruleName, ConsentToken: previewResp.Preview.ConsentToken);
        var removeResp = await _handler.HandleAsync(removeReq, callerDenial: null, CancellationToken.None);

        Assert.True(removeResp.Accepted);
        Assert.Equal("removed", removeResp.ResultCode);
        Assert.False(_backend.HasRule(ruleName));
    }

    [Fact]
    public async Task HandleAsync_PreviewAndCleanupLegacy_ExecutesWithConsent()
    {
        _backend.AddRule("downpour_v29_block", "legacy", 0, 1, true, "*", 7, "Downpour");

        // Preview
        var previewReq = new FirewallActionRequest(1, Guid.NewGuid(), FirewallActionOperations.PreviewCleanupLegacy);
        var previewResp = await _handler.HandleAsync(previewReq, callerDenial: null, CancellationToken.None);

        Assert.True(previewResp.Accepted);
        Assert.NotNull(previewResp.Preview?.ConsentToken);

        // Cleanup
        var cleanupReq = new FirewallActionRequest(1, Guid.NewGuid(), FirewallActionOperations.CleanupLegacy, ConsentToken: previewResp.Preview.ConsentToken);
        var cleanupResp = await _handler.HandleAsync(cleanupReq, callerDenial: null, CancellationToken.None);

        Assert.True(cleanupResp.Accepted);
        Assert.Equal("cleaned-up", cleanupResp.ResultCode);
        Assert.False(_backend.HasRule("downpour_v29_block"));
    }
}
