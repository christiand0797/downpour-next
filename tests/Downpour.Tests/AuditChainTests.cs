using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class AuditChainTests : IDisposable
{
    private static readonly byte[] Key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private readonly string _folder = Directory.CreateTempSubdirectory("dp-audit-").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_folder, recursive: true); } catch (IOException) { }
    }

    private static List<string> Chain(int count, long first = 1, string? previous = null)
    {
        var lines = new List<string>();
        var prev = previous ?? AuditChain.Genesis;
        for (var i = 0; i < count; i++)
        {
            lines.Add(AuditChain.Line(Key, first + i, prev, $"{{\"operation\":\"quarantine\",\"resultCode\":\"ok-{i}\"}}", out var mac));
            prev = mac;
        }
        return lines;
    }

    [Fact]
    public void IntactChainVerifies()
    {
        var result = AuditChain.Verify(Chain(25), Key);
        Assert.True(result.Intact);
        Assert.Equal(25, result.Chained);
        Assert.Equal(25, result.LastSequence);
    }

    [Fact]
    public void EditingARecordIsDetected()
    {
        var lines = Chain(10);
        lines[4] = lines[4].Replace("ok-4", "ok-X", StringComparison.Ordinal);
        var result = AuditChain.Verify(lines, Key);
        Assert.False(result.Intact);
        Assert.Equal(5, result.BrokenAtLine);
        Assert.Contains("altered", result.Message);
    }

    [Fact]
    public void DeletingOrReorderingRecordsIsDetected()
    {
        var deleted = Chain(10);
        deleted.RemoveAt(3);
        Assert.False(AuditChain.Verify(deleted, Key).Intact);

        var reordered = Chain(10);
        (reordered[2], reordered[3]) = (reordered[3], reordered[2]);
        Assert.False(AuditChain.Verify(reordered, Key).Intact);
    }

    [Fact]
    public void ForgingWithoutTheKeyIsDetected()
    {
        var lines = Chain(5);
        var forged = AuditChain.Line(Enumerable.Repeat((byte)7, 32).ToArray(), 6, "0".PadLeft(64, '0'), "{\"operation\":\"x\"}", out _);
        lines.Add(forged);
        Assert.False(AuditChain.Verify(lines, Key).Intact);
        Assert.False(AuditChain.Verify(Chain(5), Enumerable.Repeat((byte)9, 32).ToArray()).Intact);
    }

    [Fact]
    public void TruncatedTailIsDetectedThroughTheAnchor()
    {
        var lines = Chain(8);
        var full = AuditChain.Verify(lines, Key);
        var cut = lines.Take(6);
        var result = AuditChain.Verify(cut, Key, full.LastSequence, full.LastHash);
        Assert.False(result.Intact);
        Assert.Contains("deleted from the end", result.Message);
        Assert.True(AuditChain.Verify(lines, Key, full.LastSequence, full.LastHash).Intact);
    }

    [Fact]
    public void LegacyLinesAreOnlyAcceptedBeforeTheChain()
    {
        var legacy = "{\"at\":\"2026-10-01T00:00:00Z\",\"operation\":\"quarantine\",\"resultCode\":\"ok\"}";
        var before = new List<string> { legacy, legacy };
        before.AddRange(Chain(3));
        var ok = AuditChain.Verify(before, Key);
        Assert.True(ok.Intact);
        Assert.Equal(2, ok.Legacy);

        var after = Chain(3);
        after.Add(legacy);
        Assert.False(AuditChain.Verify(after, Key).Intact);
    }

    [Fact]
    public void RolledWindowMustStartWhereTheAnchorSays()
    {
        var all = Chain(10);
        var window = all.Skip(4).ToList();
        Assert.True(AuditChain.Verify(window, Key, firstSequence: 5).Intact);
        Assert.False(AuditChain.Verify(window.Skip(2), Key, firstSequence: 5).Intact);
    }

    [Fact]
    public void ActionAuditLogChainsRecordsAndDetectsTampering()
    {
        var path = Path.Combine(_folder, "audit.jsonl");
        var log = new ActionAuditLog(path);
        for (var i = 0; i < 6; i++) log.Record("quarantine", i % 2 == 0 ? "quarantined" : "denied-consent", $"obj-{i}", $"f{i}.exe");
        var intact = log.Verify();
        Assert.True(intact.Intact, intact.Message);
        Assert.Equal(6, intact.Chained);
        Assert.Contains(log.ReadRecent(3), line => line.Contains("denied-consent"));

        // A fresh instance (service restart) continues the same chain.
        var restarted = new ActionAuditLog(path);
        restarted.Record("terminate", "terminated", null, "x.exe");
        Assert.True(restarted.Verify().Intact);
        Assert.Equal(7, restarted.Verify().LastSequence);

        var text = File.ReadAllText(path);
        File.WriteAllText(path, text.Replace("\"quarantined\"", "\"restored\"", StringComparison.Ordinal));
        Assert.False(new ActionAuditLog(path).Verify().Intact);
    }

    [Fact]
    public void SeparateWritersShareOneUnbrokenChain()
    {
        var path = Path.Combine(_folder, "audit.jsonl");
        var service = new ActionAuditLog(path);
        var scheduledRelease = new ActionAuditLog(path);
        Parallel.For(0, 40, i => (i % 2 == 0 ? service : scheduledRelease).Record("host-isolation", $"step-{i}", null, null));
        var result = service.Verify();
        Assert.True(result.Intact, result.Message);
        Assert.Equal(40, result.Chained);
    }

    [Fact]
    public void TruncatingTheLogFileIsDetectedAndStaysVisible()
    {
        var path = Path.Combine(_folder, "audit.jsonl");
        var log = new ActionAuditLog(path);
        for (var i = 0; i < 5; i++) log.Record("firewall-block", "blocked", null, null);
        File.WriteAllLines(path, File.ReadAllLines(path).Take(3));

        var reopened = new ActionAuditLog(path);
        Assert.False(reopened.Verify().Intact);
        // New records continue from the anchor, so the gap is not papered over.
        reopened.Record("firewall-block", "blocked", null, null);
        Assert.False(reopened.Verify().Intact);
    }

    [Fact]
    public void MissingKeyIsReportedNotRegenerated()
    {
        var path = Path.Combine(_folder, "audit.jsonl");
        new ActionAuditLog(path).Record("quarantine", "ok", null, null);
        File.Delete(path + ".key");
        var result = new ActionAuditLog(path).Verify();
        Assert.False(result.Intact);
        Assert.Contains("key file is missing", result.Message);
        Assert.False(File.Exists(path + ".key"));
    }

    [Fact]
    public async Task MonitorRaisesACriticalFindingWhenTheChainBreaks()
    {
        var path = Path.Combine(_folder, "audit.jsonl");
        var log = new ActionAuditLog(path);
        for (var i = 0; i < 3; i++) log.Record("quarantine", "ok", null, null);
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var alerts = new SecurityAlertRepository(database.Path);
        await alerts.InitializeAsync();
        var status = Path.Combine(_folder, "status.json");
        var monitor = new AuditIntegrityMonitor(log, alerts, NullLogger<AuditIntegrityMonitor>.Instance, status);

        Assert.True((await monitor.CheckOnceAsync(CancellationToken.None)).Intact);
        Assert.Empty((await alerts.ReadSnapshotAsync()).Alerts);
        Assert.Contains("\"intact\":true", File.ReadAllText(status));

        var lines = File.ReadAllLines(path);
        File.WriteAllLines(path, [lines[0], lines[2]]);
        var broken = await new AuditIntegrityMonitor(new ActionAuditLog(path), alerts, NullLogger<AuditIntegrityMonitor>.Instance, status).CheckOnceAsync(CancellationToken.None);
        Assert.False(broken.Intact);
        var alert = Assert.Single((await alerts.ReadSnapshotAsync()).Alerts);
        Assert.Equal("CRITICAL", alert.Severity);
        Assert.Equal(SecurityFindingCatalog.Integrity, alert.LogName);
    }
}
