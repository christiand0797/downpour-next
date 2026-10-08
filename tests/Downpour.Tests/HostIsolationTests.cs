using Downpour.Service;
using Downpour.Contracts;

namespace Downpour.Tests;

public sealed class HostIsolationTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "downpour_isolation_" + Guid.NewGuid().ToString("N"));
    private readonly InMemoryFirewallPolicyBackend _firewall = new();
    private readonly FakeScheduler _scheduler = new();

    public HostIsolationTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        try { Directory.Delete(_folder, true); } catch (IOException) { }
    }

    private HostIsolationExecutor Create() => new(_firewall, new ActionAuditLog(Path.Combine(_folder, "audit.jsonl")),
        Path.Combine(_folder, "isolation.json"), lockWorkstationDelegate: () => { }, releaseScheduler: _scheduler);

    private sealed class FailingFirewall : IFirewallPolicyBackend
    {
        public readonly InMemoryFirewallPolicyBackend Inner = new();
        public bool FailInboundAdd, FailRemoval, IgnoreRemoval, FailEnumeration;
        public void AddRule(string name, string description, int action, int direction, bool enabled, string remoteAddresses, int profiles, string grouping)
        {
            if (FailInboundAdd && name == HostIsolationExecutor.RuleBlockIn) throw new IOException("Injected add failure");
            Inner.AddRule(name, description, action, direction, enabled, remoteAddresses, profiles, grouping);
        }
        public void RemoveRule(string name)
        {
            if (FailRemoval) throw new UnauthorizedAccessException("Injected removal failure");
            if (!IgnoreRemoval) Inner.RemoveRule(name);
        }
        public IReadOnlyList<FirewallRuleSummary> EnumerateRules() => FailEnumeration ? throw new IOException("Injected query failure") : Inner.EnumerateRules();
    }

    private HostIsolationExecutor Create(FailingFirewall firewall) => new(firewall, new ActionAuditLog(Path.Combine(_folder, "audit.jsonl")),
        Path.Combine(_folder, "isolation.json"), lockWorkstationDelegate: () => { }, releaseScheduler: _scheduler);

    [Fact]
    public void FailedReleasePreservesRecoveryAndCanBeRetried()
    {
        var firewall = new FailingFirewall();
        using var executor = Create(firewall);
        Assert.True(executor.Isolate(30, false, "test").Succeeded);
        firewall.FailRemoval = true;
        var failed = executor.Release("test");
        Assert.False(failed.Succeeded);
        Assert.Equal("cleanup-incomplete", failed.ResultCode);
        Assert.True(executor.IsIsolated);
        Assert.NotNull(_scheduler.Scheduled);
        Assert.Equal(0, _scheduler.Cancels);
        Assert.Contains("cleanup-incomplete", File.ReadAllText(Path.Combine(_folder, "audit.jsonl")));
        firewall.FailRemoval = false;
        Assert.True(executor.Release("retry").Succeeded);
        Assert.False(executor.IsIsolated);
        Assert.Null(_scheduler.Scheduled);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void SilentRemovalFailureOrUnverifiableAbsenceCannotClaimRelease(bool ignored, bool queryFailed)
    {
        var firewall = new FailingFirewall();
        using var executor = Create(firewall);
        executor.Isolate(30, false, "test");
        firewall.IgnoreRemoval = ignored;
        firewall.FailEnumeration = queryFailed;
        Assert.False(executor.Release("test").Succeeded);
        Assert.True(executor.IsIsolated);
        Assert.NotNull(_scheduler.Scheduled);
    }

    [Fact]
    public void PartialSetupKeepsRecoveryWhenRollbackFails()
    {
        var firewall = new FailingFirewall { FailInboundAdd = true, FailRemoval = true };
        using var executor = Create(firewall);
        var result = executor.Isolate(30, false, "test");
        Assert.False(result.Succeeded);
        Assert.Equal("rollback-incomplete", result.ResultCode);
        Assert.True(firewall.Inner.HasRule(HostIsolationExecutor.RuleBlockOut));
        Assert.True(executor.IsIsolated);
        Assert.NotNull(_scheduler.Scheduled);
        Assert.Equal(0, _scheduler.Cancels);
    }

    [Fact]
    public void PartialSetupRollsBackWhenRemovalWorks()
    {
        var firewall = new FailingFirewall { FailInboundAdd = true };
        using var executor = Create(firewall);
        var result = executor.Isolate(30, false, "test");
        Assert.False(result.Succeeded);
        Assert.Equal("firewall-error", result.ResultCode);
        Assert.Equal(0, firewall.Inner.Count);
        Assert.False(executor.IsIsolated);
        Assert.Null(_scheduler.Scheduled);
    }

    [Fact]
    public void UnwritableRecoveryStatePreventsFirewallChanges()
    {
        Directory.CreateDirectory(Path.Combine(_folder, "isolation.json"));
        using var executor = Create();
        var result = executor.Isolate(30, false, "test");
        Assert.False(result.Succeeded);
        Assert.Equal("recovery-state-error", result.ResultCode);
        Assert.Equal(0, _firewall.Count);
        Assert.Null(_scheduler.Scheduled);
    }

    [Fact]
    public void RepeatedIsolationCannotDiscardTheOriginalRecovery()
    {
        using var executor = Create();
        var first = executor.Isolate(30, false, "first");
        _scheduler.Refusal = "Unavailable";
        var second = executor.Isolate(60, false, "second");
        Assert.False(second.Succeeded);
        Assert.Equal("already-isolated", second.ResultCode);
        Assert.Equal(first.ExpiresAtUtc, _scheduler.Scheduled);
        Assert.True(executor.IsIsolated);
    }

    [Fact]
    public void FailedStartupRecoveryRemainsActiveAndScheduled()
    {
        var firewall = new FailingFirewall();
        using (var first = Create(firewall)) first.Isolate(30, false, "test");
        var path = Path.Combine(_folder, "isolation.json");
        var record = System.Text.Json.JsonSerializer.Deserialize<HostIsolationRecord>(File.ReadAllBytes(path))!;
        File.WriteAllBytes(path, System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(record with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }));
        firewall.FailRemoval = true;
        using var restarted = Create(firewall);
        Assert.True(restarted.IsIsolated);
        Assert.NotNull(_scheduler.Scheduled);
        Assert.Equal(0, _scheduler.Cancels);
    }

    [Fact]
    public async Task BrokerReturnsActualIsolationStateAfterFailedRelease()
    {
        var firewall = new FailingFirewall();
        using var executor = Create(firewall);
        executor.Isolate(30, false, "test");
        firewall.FailRemoval = true;
        var settings = new SensorSettingsStore(Path.Combine(_folder, "settings.json"));
        settings.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.HostIsolationActions, true));
        var handler = new HostIsolationHandler(executor, settings, new ActionConsentStore(), new ActionAuditLog(Path.Combine(_folder, "audit.jsonl")));
        var preview = await handler.HandleAsync(new(1, Guid.NewGuid(), HostIsolationOperations.PreviewRelease), null, CancellationToken.None);
        var response = await handler.HandleAsync(new(1, Guid.NewGuid(), HostIsolationOperations.Release, ConsentToken: preview.Preview!.ConsentToken), null, CancellationToken.None);
        Assert.False(response.Accepted);
        Assert.True(response.IsIsolated);
        Assert.Equal(executor.ActiveUntilUtc, response.ActiveUntilUtc);
        Assert.Equal("cleanup-incomplete", response.ResultCode);
    }

    [Fact]
    public async Task DisablingNewIsolationStillAllowsConsentedRecovery()
    {
        using var executor = Create();
        executor.Isolate(30, false, "test");
        var settings = new SensorSettingsStore(Path.Combine(_folder, "settings.json"));
        settings.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.HostIsolationActions, false));
        var handler = new HostIsolationHandler(executor, settings, new ActionConsentStore(), new ActionAuditLog(Path.Combine(_folder, "audit.jsonl")));
        var denied = await handler.HandleAsync(new(1, Guid.NewGuid(), HostIsolationOperations.PreviewIsolate), null, CancellationToken.None);
        Assert.False(denied.Accepted);
        var preview = await handler.HandleAsync(new(1, Guid.NewGuid(), HostIsolationOperations.PreviewRelease), null, CancellationToken.None);
        Assert.True(preview.Accepted);
        var response = await handler.HandleAsync(new(1, Guid.NewGuid(), HostIsolationOperations.Release, ConsentToken: preview.Preview!.ConsentToken), null, CancellationToken.None);
        Assert.True(response.Accepted);
        Assert.False(response.IsIsolated);
        Assert.False(response.ActionsEnabled);
        Assert.Equal(0, _firewall.Count);
    }

    [Fact]
    public async Task BrokerReturnsActualIsolationStateAfterFailedSetupRollback()
    {
        var firewall = new FailingFirewall { FailInboundAdd = true, FailRemoval = true };
        using var executor = Create(firewall);
        var settings = new SensorSettingsStore(Path.Combine(_folder, "settings.json"));
        settings.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.HostIsolationActions, true));
        var handler = new HostIsolationHandler(executor, settings, new ActionConsentStore(), new ActionAuditLog(Path.Combine(_folder, "audit.jsonl")));
        var preview = await handler.HandleAsync(new(1, Guid.NewGuid(), HostIsolationOperations.PreviewIsolate), null, CancellationToken.None);
        var response = await handler.HandleAsync(new(1, Guid.NewGuid(), HostIsolationOperations.Isolate, ConsentToken: preview.Preview!.ConsentToken), null, CancellationToken.None);
        Assert.False(response.Accepted);
        Assert.True(response.IsIsolated);
        Assert.NotNull(response.ActiveUntilUtc);
        Assert.Equal("rollback-incomplete", response.ResultCode);
    }

    private sealed class FakeScheduler : IIsolationReleaseScheduler
    {
        public string? Refusal { get; set; }
        public DateTimeOffset? Scheduled { get; private set; }
        public int Cancels { get; private set; }
        public string? Schedule(DateTimeOffset releaseAtUtc)
        {
            if (Refusal is null) Scheduled = releaseAtUtc;
            return Refusal;
        }
        public void Cancel() { Cancels++; Scheduled = null; }
    }

    [Fact]
    public void IsolationSchedulesItsOwnReleaseBeforeCuttingTheNetwork()
    {
        using var executor = Create();
        var (ok, code, _, rules, expires) = executor.Isolate(30, lockWorkstation: false, "test");
        Assert.True(ok, code);
        Assert.Equal(expires, _scheduler.Scheduled);
        Assert.Equal(2, rules.Count);
        Assert.True(_firewall.HasRule(HostIsolationExecutor.RuleBlockIn));
        Assert.True(_firewall.HasRule(HostIsolationExecutor.RuleBlockOut));
        // Allow rules would be no-ops (block rules win), so none are created.
        Assert.False(_firewall.HasRule(HostIsolationExecutor.RuleAllowLoopbackIn));
    }

    [Fact]
    public void IsolationIsRefusedWhenTheReleaseCannotBeScheduled()
    {
        _scheduler.Refusal = "Task Scheduler unavailable";
        using var executor = Create();
        var (ok, code, message, _, _) = executor.Isolate(30, false, "test");
        Assert.False(ok);
        Assert.Equal("denied-release-unscheduled", code);
        Assert.Contains("Task Scheduler", message);
        Assert.Equal(0, _firewall.Count);
        Assert.False(executor.IsIsolated);
    }

    [Fact]
    public void ManualReleaseRemovesRulesAndTheScheduledTask()
    {
        using var executor = Create();
        executor.Isolate(30, false, "test");
        var (ok, code, _) = executor.Release("done");
        Assert.True(ok);
        Assert.Equal("released", code);
        Assert.Equal(0, _firewall.Count);
        Assert.Null(_scheduler.Scheduled);
        Assert.False(executor.IsIsolated);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(1441)]
    public void DurationMustBeBounded(int minutes)
    {
        using var executor = Create();
        Assert.False(executor.Isolate(minutes, false, "test").Succeeded);
        Assert.Equal(0, _firewall.Count);
        Assert.Null(_scheduler.Scheduled);
    }

    [Fact]
    public void ExpiredIsolationIsReleasedAtStartup()
    {
        using (var first = Create()) first.Isolate(30, false, "test");
        // Simulate the expiry passing while the service was not running.
        var path = Path.Combine(_folder, "isolation.json");
        var record = System.Text.Json.JsonSerializer.Deserialize<HostIsolationRecord>(File.ReadAllBytes(path))!;
        File.WriteAllBytes(path, System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(record with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }));
        using var restarted = Create();
        Assert.False(restarted.IsIsolated);
        Assert.Equal(0, _firewall.Count);
    }
}
