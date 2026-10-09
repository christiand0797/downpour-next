using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class LocalLearningTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
    private static LocalLearningFrame Frame(DateTimeOffset at, double? cpu = 10, double? memory = 40, double? connections = 10, double? processes = 100) =>
        new(at, cpu, memory, connections, processes);
    private static SecurityAlertSnapshot Alerts(DateTimeOffset? at = null) => new(1, at ?? Now, 0, [], []);
    private static LocalLearningHistory Trained(int buckets = 24)
    {
        var history = LocalLearningEngine.Empty;
        for (var i = buckets; i > 0; i--)
        {
            var at = Now.AddMinutes(-5 * i);
            history = LocalLearningEngine.Observe(history, Frame(at), at);
        }
        return history;
    }

    [Fact]
    public void EmptyAndMissingHistoryNeverBecomeLearnedQuietTime()
    {
        var reading = LocalLearningEngine.Assess(LocalLearningEngine.Empty, Frame(Now), Alerts(), Now);
        Assert.Equal("learning", reading.State);
        Assert.All(reading.Metrics, m => { Assert.Null(m.Normal); Assert.Equal(0, m.BaselineBuckets); });
        Assert.True(LocalLearningClient.IsValid(reading, Now));
    }

    [Fact]
    public void ObservedBucketsProduceAnExplainableBaseline()
    {
        var reading = LocalLearningEngine.Assess(Trained(), Frame(Now), Alerts(), Now);
        Assert.Equal("observing", reading.State);
        Assert.Equal(10, reading.Metrics[0].Normal);
        Assert.Equal(20, reading.Metrics[0].Threshold);
        Assert.Equal(24, reading.HistoryBuckets);
        Assert.Empty(reading.Recommendations);
        Assert.True(LocalLearningClient.IsValid(reading, Now));
    }

    [Fact]
    public void CurrentSpikeCannotTrainAwayItsOwnAnomaly()
    {
        var frame = Frame(Now, cpu: 95, connections: 500);
        var history = LocalLearningEngine.Observe(Trained(), frame, Now);
        var reading = LocalLearningEngine.Assess(history, frame, Alerts(), Now);
        Assert.Equal("unusual", reading.Metrics[0].State);
        Assert.Equal("unusual", reading.Metrics[2].State);
        Assert.Equal(10, reading.Metrics[0].Normal);
        Assert.Equal(24, reading.Metrics[0].BaselineBuckets);
        Assert.Contains(reading.Recommendations, r => r.Id == "resources");
        Assert.Contains(reading.Recommendations, r => r.Id == "connections");
    }

    [Fact]
    public void ABriefHistoricalOutlierDoesNotMoveTheMedian()
    {
        var history = Trained() with { Buckets = Trained().Buckets.Select((b, i) => i != 0 ? b : b with
        { Metrics = [new(1, 99), new(1, 99), new(1, 9999), new(1, 9999)] }).ToArray() };
        Assert.Equal(10, LocalLearningEngine.Assess(history, Frame(Now), Alerts(), Now).Metrics[0].Normal);
    }

    [Fact]
    public void DuplicateMinuteAndBackwardReadAreNotLearnedAgain()
    {
        var first = LocalLearningEngine.Observe(LocalLearningEngine.Empty, Frame(Now), Now);
        Assert.Same(first, LocalLearningEngine.Observe(first, Frame(Now.AddSeconds(30), cpu: 99), Now.AddSeconds(30)));
        Assert.Same(first, LocalLearningEngine.Observe(first, Frame(Now.AddSeconds(-15)), Now));
        Assert.All(first.Buckets[0].Metrics, m => Assert.Equal(1, m.Count));
    }

    [Fact]
    public void MissingMetricRemainsUnknownAndDoesNotDiluteAnAverage()
    {
        var history = LocalLearningEngine.Observe(LocalLearningEngine.Empty, Frame(Now, cpu: null), Now);
        Assert.Equal(0, history.Buckets[0].Metrics[0].Count);
        history = LocalLearningEngine.Observe(history, Frame(Now.AddMinutes(1), cpu: 80), Now.AddMinutes(1));
        Assert.Equal(1, history.Buckets[0].Metrics[0].Count);
        Assert.Equal(80, history.Buckets[0].Metrics[0].Mean);
        var reading = LocalLearningEngine.Assess(Trained(), Frame(Now, cpu: null), Alerts(), Now);
        Assert.Equal("unavailable", reading.Metrics[0].State);
        Assert.Equal("partial", reading.State);
    }

    [Fact]
    public void LongOfflineGapDoesNotInventSamples()
    {
        var history = LocalLearningEngine.Observe(LocalLearningEngine.Empty, Frame(Now.AddDays(-3)), Now.AddDays(-3));
        history = LocalLearningEngine.Observe(history, Frame(Now), Now);
        var reading = LocalLearningEngine.Assess(history, Frame(Now), Alerts(), Now);
        Assert.Equal(1, reading.HistoryBuckets);
        Assert.Equal("learning", reading.State);
    }

    [Fact]
    public void HistoryExpiresAndRemainsBounded()
    {
        var history = Trained(LocalLearningEngine.MaximumBuckets);
        history = LocalLearningEngine.Observe(history, Frame(Now), Now);
        Assert.Equal(LocalLearningEngine.MaximumBuckets, history.Buckets.Count);
        Assert.True(LocalLearningEngine.IsValidHistory(history, Now));
        Assert.True(BoundedJson.Serialize(history).Length < LocalLearningStore.MaximumBytes);
        Assert.Empty(LocalLearningEngine.Prune(history, Now.AddDays(8)).Buckets);
        Assert.Equal("learning", LocalLearningEngine.Assess(history, Frame(Now.AddDays(8)), Alerts(Now.AddDays(8)), Now.AddDays(8)).State);
    }

    [Fact]
    public void PausedEngineReturnsNoCurrentReadingsOrRecommendations()
    {
        var reading = LocalLearningEngine.Assess(Trained(), Frame(Now, cpu: 99), Alerts(), Now, enabled: false);
        Assert.Equal("paused", reading.State);
        Assert.All(reading.Metrics, m => { Assert.Equal("paused", m.State); Assert.Null(m.Current); });
        Assert.Empty(reading.Recommendations);
    }

    [Fact]
    public void StaleTelemetryIsUnavailableRatherThanHealthy()
    {
        var reading = LocalLearningEngine.Assess(Trained(), Frame(Now.AddMinutes(-10)), Alerts(), Now);
        Assert.Equal("unavailable", reading.State);
        Assert.All(reading.Metrics, m => Assert.Null(m.Current));
        Assert.Contains(reading.Warnings, w => w.Contains("stale"));
    }

    [Fact]
    public void CorrelationIsBasedOnRecentOpenUrgentEvidenceAndExplainsItsLimit()
    {
        var alert = new SecurityAlert(new string('a',64), "test", "HIGH", "T1041", "System", "test", 1, null,
            Now, Now, Now, 1, "Open");
        var alerts = Alerts() with { TotalCount = 1, Alerts = [alert] };
        var reading = LocalLearningEngine.Assess(Trained(), Frame(Now, connections: 200), alerts, Now);
        var correlation = Assert.Single(reading.Recommendations, r => r.Id == "network-context");
        Assert.Contains("not proof", correlation.Explanation);
        Assert.True(LocalLearningClient.IsValid(reading, Now));
        foreach (var excluded in new[] { alert with { State = "Suppressed" }, alert with { LastSeenUtc = Now.AddHours(-1) }, alert with { Severity = "LOW" } })
            Assert.DoesNotContain(LocalLearningEngine.Assess(Trained(), Frame(Now, connections: 200), alerts with { Alerts = [excluded] }, Now).Recommendations,
                r => r.Id == "network-context");
        Assert.DoesNotContain(LocalLearningEngine.Assess(Trained(), Frame(Now, connections: 200), alerts with { CapturedAtUtc = Now.AddHours(-1) }, Now).Recommendations,
            r => r.Id == "network-context");
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(-1)]
    [InlineData(101)]
    public void InvalidMetricCannotPoisonHistory(double cpu)
    {
        Assert.Throws<InvalidDataException>(() => LocalLearningEngine.Observe(LocalLearningEngine.Empty, Frame(Now, cpu), Now));
    }

    [Fact]
    public void DamagedHistoryIsRejectedWithoutThrowing()
    {
        var history = Trained();
        Assert.False(LocalLearningEngine.IsValidHistory(history with { Buckets = null! }, Now));
        Assert.False(LocalLearningEngine.IsValidHistory(history with { Buckets = [null!] }, Now));
        Assert.False(LocalLearningEngine.IsValidHistory(history with { Buckets = [history.Buckets[0], history.Buckets[0]] }, Now));
        Assert.False(LocalLearningEngine.IsValidHistory(history with { LastObservationUtc = Now.AddDays(1) }, Now));
        Assert.False(LocalLearningEngine.IsValidHistory(history with { Buckets = [history.Buckets[0] with { Metrics = [null!, new(1,0),new(1,0),new(1,0)] }] }, Now));
        var reading = LocalLearningEngine.Assess(history with { SchemaVersion = 99 }, Frame(Now), Alerts(), Now);
        Assert.Equal("learning", reading.State);
        Assert.Contains(reading.Warnings, w => w.Contains("invalid"));
    }

    [Fact]
    public void ClientRejectsStaleMalformedOrMisroutedReplies()
    {
        var reading = LocalLearningEngine.Assess(Trained(), Frame(Now), Alerts(), Now);
        Assert.False(LocalLearningClient.IsValid(reading with { CapturedAtUtc = Now.AddHours(-1) }, Now));
        Assert.False(LocalLearningClient.IsValid(reading with { Metrics = [null!, null!, null!, null!] }, Now));
        Assert.False(LocalLearningClient.IsValid(reading with { State = "fully-protected" }, Now));
        Assert.False(LocalLearningClient.IsValid(reading with { Recommendations = [new("x", "x", "x", "cmd.exe")] }, Now));
        Assert.False(LocalLearningClient.IsValid(reading with { Warnings = ["line\nbreak"] }, Now));
        Assert.False(LocalLearningClient.IsValid(reading with { Metrics = reading.Metrics.Select(m => m with { Current = double.NaN }).ToArray() }, Now));
        Assert.False(LocalLearningClient.IsValid(reading with { Metrics = reading.Metrics.Select(m => m with { Current = 200 }).ToArray() }, Now));
        Assert.False(LocalLearningClient.IsValid(reading with { Metrics = reading.Metrics.Select(m => m with { State = "unusual" }).ToArray() }, Now));
    }

    [Fact]
    public async Task HistorySurvivesRestartAndCorruptFilesFailVisibly()
    {
        var folder = Path.Combine(Path.GetTempPath(), "DownpourLearningTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, "history.json");
        try
        {
            var store = new LocalLearningStore(path);
            Assert.True(await store.SaveAsync(Trained(), Now, default));
            var loaded = await new LocalLearningStore(path).LoadAsync(Now, default);
            Assert.Null(loaded.Warning);
            Assert.Equal(24, loaded.History.Buckets.Count);
            Assert.Equal("observing", LocalLearningEngine.Assess(loaded.History, Frame(Now), Alerts(), Now).State);
            await File.WriteAllTextAsync(path, "{\"SchemaVersion\":1,\"Buckets\":null}");
            loaded = await store.LoadAsync(Now, default);
            Assert.NotNull(loaded.Warning);
            Assert.Empty(loaded.History.Buckets);
            await File.WriteAllTextAsync(path, new string(' ', LocalLearningStore.MaximumBytes + 1));
            Assert.NotNull((await store.LoadAsync(Now, default)).Warning);
            Assert.False(await new LocalLearningStore(Path.Combine(folder, "missing", "x.json")).SaveAsync(Trained(), Now, default));
        }
        finally { Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public void HistorySerializationContainsOnlyAggregates()
    {
        var raw = Encoding.UTF8.GetString(BoundedJson.Serialize(Trained()));
        Assert.DoesNotContain("ProcessName", raw);
        Assert.DoesNotContain("Address", raw);
        Assert.DoesNotContain("Path", raw);
        Assert.True(LocalLearningEngine.IsValidHistory(BoundedJson.Deserialize<LocalLearningHistory>(Encoding.UTF8.GetBytes(raw)), Now));
    }
}
