using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

/// <summary>
/// Regressions for "sensor service did not answer" on other PCs: hostile or long download errors and damaged saved
/// copies must never make the whole snapshot fail validation, failures must be described usefully, and slow but steady
/// downloads must complete while stalled ones fail.
/// </summary>
public sealed class ThreatDatabaseResilienceTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("dp-tdb-res-").FullName;

    public void Dispose()
    {
        try { Directory.Delete(_folder, recursive: true); } catch (IOException) { }
    }

    private ThreatDatabaseService CreateService(HttpMessageHandler handler) => new(
        new SecurityAlertRepository(Path.Combine(_folder, "alerts.db")),
        new SensorSettingsStore(Path.Combine(_folder, "settings.json")),
        new DnsInventoryProvider(Path.Combine(_folder, "dns.json")),
        new DriverInventoryProvider(),
        NullLogger<ThreatDatabaseService>.Instance,
        new ThreatFeedCache(Path.Combine(_folder, "cache")),
        new ThreatFeedDownloader(new HttpClient(handler)),
        "Downpour.Test.ThreatDb." + Guid.NewGuid().ToString("N"));

    private sealed class ThrowingHandler(Exception exception) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => throw exception;
    }

    [Fact]
    public async Task HostileDownloadErrorsStillProduceAValidSnapshot()
    {
        var message = "proxy said:\r\n" + new string('x', 2000) + "\u0007\u001b[31m";
        using var service = CreateService(new ThrowingHandler(new HttpRequestException(message)));
        service.LoadCaches();
        await service.RefreshDueAsync(force: true, default);

        var snapshot = service.Snapshot();
        Assert.True(ThreatDatabaseClient.IsValid(snapshot));
        Assert.All(snapshot.Feeds, f =>
        {
            Assert.Equal(ThreatFeedStates.Failed, f.State);
            Assert.True(f.Error!.Length <= 300);
            Assert.DoesNotContain(f.Error, c => char.IsControl(c));
        });
        var reply = await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Snapshot, null), default);
        Assert.True(ThreatDatabaseClient.IsValid(reply));
    }

    [Fact]
    public async Task UnexpectedExceptionTypesStayWithTheirDatabase()
    {
        using var service = CreateService(new ThrowingHandler(new NotSupportedException("odd platform")));
        service.LoadCaches();
        await service.RefreshDueAsync(force: true, default);
        Assert.All(service.Snapshot().Feeds, f => Assert.Contains("odd platform", f.Error));
    }

    [Fact]
    public void DamagedSavedCopiesDoNotBreakTheSnapshot()
    {
        var cache = Path.Combine(_folder, "cache");
        Directory.CreateDirectory(cache);
        foreach (var feed in ThreatFeedCatalog.All)
            File.WriteAllBytes(Path.Combine(cache, feed.Id + ".v1.cache"), [.. "DPTDB001"u8, 1, 2, 3, 255, 0, 13, 10]);
        using var service = CreateService(new ThrowingHandler(new HttpRequestException("offline")));
        service.LoadCaches();
        Assert.True(ThreatDatabaseClient.IsValid(service.Snapshot()));
    }

    [Fact]
    public void FailuresAreDescribedInActionableWords()
    {
        Assert.Contains("could not be resolved", ThreatDatabaseService.DescribeFailure(
            new HttpRequestException("No such host is known.", new SocketException((int)SocketError.HostNotFound))));
        Assert.Contains("firewall, VPN or proxy", ThreatDatabaseService.DescribeFailure(
            new HttpRequestException("x", new SocketException((int)SocketError.ConnectionRefused))));
        Assert.Contains("clock", ThreatDatabaseService.DescribeFailure(
            new HttpRequestException("The SSL connection could not be established", new AuthenticationException("remote certificate invalid"))));
        Assert.Equal("The source answered HTTP 503.", ThreatDatabaseService.DescribeFailure(new HttpRequestException("The source answered HTTP 503.")));
    }

    /// <summary>Serves a body in small chunks with a delay between them.</summary>
    private sealed class TrickleHandler(int chunks, TimeSpan delay, TimeSpan? stallAfterFirst = null) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new TrickleStream(chunks, delay, stallAfterFirst)), RequestMessage = request });
    }

    private sealed class TrickleStream(int chunks, TimeSpan delay, TimeSpan? stallAfterFirst) : Stream
    {
        private int _sent;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_sent >= chunks) return 0;
            await Task.Delay(_sent == 1 && stallAfterFirst is { } stall ? stall : delay, cancellationToken);
            var line = "1.2.3.4\n"u8;
            line.CopyTo(buffer.Span);
            _sent++;
            return line.Length;
        }
    }

    [Fact]
    public async Task SlowButSteadyDownloadsFinishAndStalledOnesFail()
    {
        var feed = ThreatFeedCatalog.Find("cins")!;
        var steady = new ThreatFeedDownloader(new HttpClient(new TrickleHandler(12, TimeSpan.FromMilliseconds(80))), stallTimeout: TimeSpan.FromMilliseconds(400));
        var payload = await steady.FetchAsync(feed, default);
        Assert.Equal(12 * 8, payload.Length);

        var stalled = new ThreatFeedDownloader(new HttpClient(new TrickleHandler(5, TimeSpan.FromMilliseconds(10), TimeSpan.FromSeconds(5))), stallTimeout: TimeSpan.FromMilliseconds(400));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stalled.FetchAsync(feed, default));
    }

    [Fact]
    public async Task ClientExplainsWhyTheServiceDidNotAnswer()
    {
        var client = new ThreatDatabaseClient("Downpour.Test.Missing." + Guid.NewGuid().ToString("N"));
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        Assert.Null(await client.GetSnapshotAsync(cancel.Token));
        Assert.Contains("not running or not reachable", client.FailureMessage);
    }
}
