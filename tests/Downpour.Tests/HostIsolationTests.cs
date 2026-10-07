using Downpour.Service;

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
