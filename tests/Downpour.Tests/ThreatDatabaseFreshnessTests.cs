using System.Net;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class ThreatDatabaseFreshnessTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("dp-freshness-").FullName;
    private sealed class TestTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class OfflineHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { RequestMessage = request });
    }
    private ThreatFeedCache Cache => new(Path.Combine(_folder, "cache"));
    private SecurityAlertRepository Alerts => new(Path.Combine(_folder, "alerts.db"));
    private ThreatDatabaseService Service(TestTime time) => new(Alerts, new SensorSettingsStore(Path.Combine(_folder, "settings.json")),
        new DnsInventoryProvider(Path.Combine(_folder, "dns.json")), new DriverInventoryProvider(), NullLogger<ThreatDatabaseService>.Instance,
        Cache, new ThreatFeedDownloader(new HttpClient(new OfflineHandler())), "Downpour.Freshness." + Guid.NewGuid().ToString("N"), timeProvider: time);
    private void Save(string id, string content, DateTimeOffset downloaded) => Cache.Write(ThreatFeedCatalog.Find(id)!, Encoding.UTF8.GetBytes(content), downloaded);
    private static ThreatMatch Match(DateTimeOffset now) => new(now, ThreatMatchPlaces.Dns, "listed.example", "Fixture", "blp-phishing", "Fixture source", "Fixture label", "MEDIUM", "T1566");

    [Fact]
    public void ConcurrentRefreshAndObsoleteScanSignalsCoalesceWithoutFailing()
    {
        using var service = Service(new TestTime());
        Parallel.For(0, 1000, _ => service.SignalSweep());
    }

    [Fact]
    public async Task ExpiredPublicationIsExcludedOnLoadButRemainsBrowsable()
    {
        var time = new TestTime();
        Save("blp-phishing", "# Last modified: 2026-07-06 00:40:29 UTC\nlisted.example", time.Now);
        using var service = Service(time);
        service.LoadCaches();
        Assert.Empty(service.Index.LookupExact("listed.example"));
        var status = service.Snapshot().Feeds.Single(f => f.Id == "blp-phishing");
        Assert.Equal(ThreatSourceFreshness.Expired, status.SourceFreshness);
        Assert.False(status.MatchingEnabled);
        var lookup = await service.HandleAsync(new(1, ThreatDatabaseOperations.Lookup, "listed.example"), default);
        Assert.Empty(lookup.LookupHits!);
        var browse = await service.HandleAsync(new(1, ThreatDatabaseOperations.Browse, null, "blp-phishing"), default);
        Assert.Single(browse.Browse!);
        Assert.True(ThreatDatabaseClient.IsValid(service.Snapshot()));
    }

    [Fact]
    public async Task ExpiryRemovesRetainedMatchesWithoutChangingCentralOperatorTriage()
    {
        await Alerts.InitializeAsync(default);
        var time = new TestTime();
        Save("blp-phishing", "# Last modified: 2026-09-20 12:00:00 UTC\nlisted.example", time.Now);
        using var service = Service(time);
        service.LoadCaches();
        Assert.True(await service.PublishMatchesAsync([Match(time.Now)], time.Now, service.Index, default));
        Assert.Single(service.Snapshot().Matches);
        var before = Assert.Single((await Alerts.ReadSnapshotAsync(default)).Alerts);
        Assert.Equal("Open", before.State);
        time.Now = time.Now.AddDays(2);
        await service.ReevaluateFreshnessAsync(default);
        Assert.Empty(service.Snapshot().Matches);
        Assert.Empty(service.Index.LookupExact("listed.example"));
        var after = Assert.Single((await Alerts.ReadSnapshotAsync(default)).Alerts);
        Assert.Equal(before.State, after.State);
        Assert.Equal(before.LastSeenUtc, after.LastSeenUtc);
        Assert.Contains(service.Snapshot().Warnings, warning => warning.Contains("dated observations", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DelayedSweepUsingAnOlderIndexCannotPublishAfterSourceExpiry()
    {
        await Alerts.InitializeAsync(default);
        var time = new TestTime();
        Save("blp-phishing", "# Last modified: 2026-09-20 12:00:00 UTC\nlisted.example", time.Now);
        using var service = Service(time);
        service.LoadCaches();
        var captured = service.Index;
        var observed = time.Now;
        time.Now = time.Now.AddDays(2);
        Assert.False(await service.PublishMatchesAsync([Match(observed)], observed, captured, default));
        Assert.Empty(service.Snapshot().Matches);
        Assert.Empty((await Alerts.ReadSnapshotAsync(default)).Alerts);
    }

    [Fact]
    public async Task FailedRefreshDoesNotKeepAnExpiredInMemoryCopyActive()
    {
        var time = new TestTime();
        Save("stalkerware", "listed.example", time.Now);
        using var service = Service(time);
        service.LoadCaches();
        Assert.Single(service.Index.LookupExact("listed.example"));
        time.Now = time.Now.AddDays(31);
        Assert.Equal(0, await service.RefreshDueAsync(true, default));
        await service.ReevaluateFreshnessAsync(default);
        Assert.Empty(service.Index.LookupExact("listed.example"));
        Assert.False(service.Snapshot().Feeds.Single(f => f.Id == "stalkerware").MatchingEnabled);
    }

    [Theory]
    [InlineData("http")]
    [InlineData("https")]
    [InlineData("ftp")]
    public async Task MalformedDeferredIdnLookupIsRejectedWithoutThrowing(string scheme)
    {
        using var service = Service(new TestTime());
        var response = await service.HandleAsync(new(1, ThreatDatabaseOperations.Lookup, scheme + "://\u200d.example/payload"), default);
        Assert.False(response.Accepted);
        Assert.Equal("unrecognized", response.ResultCode);
    }

    [Fact]
    public async Task BrowsePagesSearchCompleteSourceAndRejectInvalidOffsets()
    {
        var time = new TestTime();
        Save("stalkerware", string.Join('\n', Enumerable.Range(0, 550).Select(i => $"item{i}.example")), time.Now);
        using var service = Service(time);
        service.LoadCaches();
        var page = await service.HandleAsync(new(1, ThreatDatabaseOperations.Browse, null, "stalkerware", 500), default);
        Assert.Equal(550, page.BrowseTotal);
        Assert.Equal(500, page.BrowseOffset);
        Assert.Equal(50, page.Browse!.Count);
        Assert.Null(page.BrowseNextOffset);
        Assert.True(ThreatDatabaseClient.IsValid(page));
        Assert.False((await service.HandleAsync(new(1, ThreatDatabaseOperations.Browse, null, "stalkerware", -1), default)).Accepted);
        Assert.False((await service.HandleAsync(new(1, ThreatDatabaseOperations.Snapshot, null, Offset: 1), default)).Accepted);
    }

    [Fact]
    public void CompleteProvenanceBeyondOldDisplayLimitSurvivesAssessmentAndContractValidation()
    {
        using var service = Service(new TestTime());
        var feeds = ThreatFeedCatalog.All.Where(f => f.Kind == ThreatFeedKinds.Domain).ToArray();
        var match = ThreatDatabaseService.Assess(DateTimeOffset.UtcNow,
            new ThreatEvidence(ThreatMatchPlaces.Dns, "listed.example", feeds.Select(f => (f, "Fixture")).ToArray()), "Fixture");
        Assert.True(match.FeedId.Length > 128);
        Assert.Equal(feeds.Select(f => f.Id), match.FeedId.Split(','));
        var snapshot = service.Snapshot() with { Matches = [match] };
        Assert.True(ThreatDatabaseClient.IsValid(snapshot));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { Matches = [match with { FeedId = "a,b,…" }] }));
    }

    [Fact]
    public void ClientAcceptsLegacyOptionalMetadataButRejectsContradictions()
    {
        using var service = Service(new TestTime());
        var snapshot = service.Snapshot();
        var feed = snapshot.Feeds[0] with { SourceFreshness = null, MatchingEnabled = null, FreshnessNote = null };
        Assert.True(ThreatDatabaseClient.IsValid(snapshot with { Feeds = [feed] }));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { Feeds = [feed with { SourceFreshness = "invented" }] }));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { Feeds = [feed with { SourceFreshness = ThreatSourceFreshness.Fresh }] }));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { Feeds = [feed with { SourcePublishedAtUtc = DateTimeOffset.MaxValue }] }));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { Feeds = [feed with { SourceFreshness = ThreatSourceFreshness.Expired, MatchingEnabled = true }] }));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { Feeds = [feed with { FreshnessNote = "bad\nmetadata" }] }));
    }

    public void Dispose()
    {
        try { Directory.Delete(_folder, true); } catch (IOException) { }
    }
}
