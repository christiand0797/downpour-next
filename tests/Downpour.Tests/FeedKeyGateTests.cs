using System.Net;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

/// <summary>
/// The abuse.ch exports answer HTTP 410 without a key, so they stay inactive until a free Auth-Key is stored and then
/// download with it. PhishTank's retirement is not key-gated and must stay off even when a key exists.
/// </summary>
public sealed class FeedKeyGateTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("dp-feed-key-").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_folder, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public void OnlyKeyedRetirementCanActivate()
    {
        var open = ThreatFeedCatalog.All.First(feed => !feed.Retired);
        Assert.True(ThreatFeedEnablement.IsActive(open, null));

        var keyed = ThreatFeedCatalog.All.First(feed => feed.AuthKeyService is not null);
        Assert.False(ThreatFeedEnablement.IsActive(keyed, null));
        Assert.False(ThreatFeedEnablement.IsActive(keyed, _ => null));
        Assert.False(ThreatFeedEnablement.IsActive(keyed, service => service == ThreatFeedAuth.AbuseCh ? "" : "other"));
        Assert.True(ThreatFeedEnablement.IsActive(keyed, service => service == ThreatFeedAuth.AbuseCh ? "stored-key" : null));

        var phishtank = ThreatFeedCatalog.All.First(feed => feed.Id == "phishtank");
        Assert.False(ThreatFeedEnablement.IsActive(phishtank, _ => "stored-key"));
    }

    [Fact]
    public void KeyStoreAcceptsTheFeedKeyAndAnnouncesChanges()
    {
        var keys = new IntelKeyStore(Path.Combine(_folder, "keys.json"));
        var raised = 0;
        keys.Changed += () => raised++;

        Assert.True(keys.Set(ThreatFeedAuth.AbuseCh, "test-key-123456"));
        Assert.Contains(ThreatFeedAuth.AbuseCh, keys.ConfiguredServices);
        Assert.Equal(1, raised);

        Assert.False(keys.Set("NotAProvider", "x"));
        Assert.True(keys.Set(ThreatFeedAuth.AbuseCh, null));
        Assert.DoesNotContain(ThreatFeedAuth.AbuseCh, keys.ConfiguredServices);
        Assert.Equal(2, raised);
    }

    [Fact]
    public async Task FeedsDownloadOnlyAfterTheKeyIsStored()
    {
        var keys = new IntelKeyStore(Path.Combine(_folder, "keys.json"));
        var handler = new RecordingHandler();
        using var service = CreateService(handler, keys);
        service.LoadCaches();

        Assert.DoesNotContain(service.Snapshot().Feeds, feed => feed.Id == "threatfox");
        Assert.Contains(service.Snapshot().Warnings, warning => warning.Contains("abuse.ch"));
        await service.RefreshDueAsync(force: true, default);
        Assert.DoesNotContain(handler.Requests, request => request.Url.Contains("threatfox.abuse.ch"));
        Assert.All(handler.Requests, request => Assert.Null(request.AuthKey));

        Assert.True(keys.Set(ThreatFeedAuth.AbuseCh, "test-key-123456"));
        await service.RefreshDueAsync(force: true, default);

        var threatFox = handler.Requests.Single(request => request.Url.Contains("threatfox.abuse.ch"));
        Assert.Equal("test-key-123456", threatFox.AuthKey);
        Assert.Contains(handler.Requests, request => request.Url.Contains("urlhaus.abuse.ch"));
        Assert.Contains(handler.Requests, request => request.Url.Contains("bazaar.abuse.ch"));
        var listed = service.Snapshot().Feeds.Single(feed => feed.Id == "threatfox");
        // The test handler refuses every download, so the feed is listed and reported as failed rather than hidden.
        Assert.Equal(ThreatFeedStates.Failed, listed.State);
        Assert.DoesNotContain(service.Snapshot().Warnings, warning => warning.Contains("stay off"));
    }

    private ThreatDatabaseService CreateService(RecordingHandler handler, IntelKeyStore keys) => new(
        new SecurityAlertRepository(Path.Combine(_folder, "alerts.db")),
        new SensorSettingsStore(Path.Combine(_folder, "settings.json")),
        new DnsInventoryProvider(Path.Combine(_folder, "dns.json")),
        new DriverInventoryProvider(),
        NullLogger<ThreatDatabaseService>.Instance,
        new ThreatFeedCache(Path.Combine(_folder, "cache")),
        new ThreatFeedDownloader(new HttpClient(handler), apiKeyProvider: service => keys.Get(service)),
        "Downpour.Test.FeedKey." + Guid.NewGuid().ToString("N"),
        feedKeys: keys);

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<(string Url, string? AuthKey)> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var authKey = request.Headers.TryGetValues(ThreatFeedAuth.AbuseChHeader, out var values) ? values.FirstOrDefault() : null;
            lock (Requests) Requests.Add((request.RequestUri!.ToString(), authKey));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
        }
    }
}
