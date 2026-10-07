using System.Net;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class IntelIndicatorTests
{
    private static SecurityAlert Alert(string title, string source = SecurityFindingCatalog.RemoteAccess)
    {
        var now = DateTimeOffset.UtcNow;
        return new SecurityAlert(new string('a', 64), title, "HIGH", "T1", source, new string('b', 32), 0, null, now, now, now, 1, "Open");
    }

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.20.0.1", false)]
    [InlineData("192.168.1.10", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.3.4", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("203.0.113.5", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("fd00::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("2001:db8::1", false)]
    public void OnlyPublicAddressesQualify(string address, bool expected) =>
        Assert.Equal(expected, IntelIndicatorExtractor.IsPublic(IPAddress.Parse(address)));

    [Fact]
    public void ExtractsPublicIpsAndHashesButNeverFileNamesAsDomains()
    {
        var hash = new string('c', 64);
        var indicators = IntelIndicatorExtractor.FromAlert(Alert($"beacon.exe connected to 8.8.4.4:4444 and 192.168.0.5; payload {hash} from report.pdf"));
        Assert.Contains(indicators, i => i.Kind == IntelKinds.Ip && i.Value == "8.8.4.4");
        Assert.Contains(indicators, i => i.Kind == IntelKinds.Hash && i.Value == hash);
        Assert.DoesNotContain(indicators, i => i.Value == "192.168.0.5");
        Assert.DoesNotContain(indicators, i => i.Kind == IntelKinds.Domain);
    }

    [Fact]
    public void DomainsComeOnlyFromDnsFindings()
    {
        var dns = IntelIndicatorExtractor.FromAlert(Alert("DGA-like domain observed in resolver cache: xkqzvbtr9a.example (Risk 90: entropy)", SecurityFindingCatalog.Dns));
        Assert.Contains(dns, i => i.Kind == IntelKinds.Domain && i.Value == "xkqzvbtr9a.example");
        var other = IntelIndicatorExtractor.FromAlert(Alert("DGA-like domain observed in resolver cache: xkqzvbtr9a.example (Risk 90)", SecurityFindingCatalog.Firewall));
        Assert.DoesNotContain(other, i => i.Kind == IntelKinds.Domain);
    }
}

public sealed class IntelProviderTests
{
    private static readonly IntelIndicator Ip = new(IntelKinds.Ip, "8.8.8.8");
    private static byte[] Json(string text) => Encoding.UTF8.GetBytes(text);

    [Theory]
    [InlineData(5, 0, IntelVerdicts.Malicious)]
    [InlineData(1, 0, IntelVerdicts.Suspicious)]
    [InlineData(0, 2, IntelVerdicts.Suspicious)]
    [InlineData(0, 0, IntelVerdicts.Clean)]
    public void VirusTotalVerdicts(int malicious, int suspicious, string verdict)
    {
        var body = Json("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":" + malicious + ",\"suspicious\":" + suspicious + ",\"harmless\":60,\"undetected\":10}}}}");
        Assert.Equal(verdict, IntelProviders.Parse(IntelServices.VirusTotal, Ip, HttpStatusCode.OK, body, DateTimeOffset.UtcNow).Verdict);
    }

    [Theory]
    [InlineData(90, IntelVerdicts.Malicious)]
    [InlineData(40, IntelVerdicts.Suspicious)]
    [InlineData(0, IntelVerdicts.Clean)]
    public void AbuseIpDbVerdicts(int score, string verdict)
    {
        var body = Json($$$"""{"data":{"abuseConfidenceScore":{{{score}}},"totalReports":7}}""");
        Assert.Equal(verdict, IntelProviders.Parse(IntelServices.AbuseIpDb, Ip, HttpStatusCode.OK, body, DateTimeOffset.UtcNow).Verdict);
    }

    [Fact]
    public void GreyNoiseAndErrorsMapConservatively()
    {
        Assert.Equal(IntelVerdicts.Malicious, IntelProviders.Parse(IntelServices.GreyNoise, Ip, HttpStatusCode.OK, Json("""{"classification":"malicious"}"""), DateTimeOffset.UtcNow).Verdict);
        Assert.Equal(IntelVerdicts.Clean, IntelProviders.Parse(IntelServices.GreyNoise, Ip, HttpStatusCode.OK, Json("""{"classification":"unknown","riot":true}"""), DateTimeOffset.UtcNow).Verdict);
        Assert.Equal(IntelVerdicts.Unknown, IntelProviders.Parse(IntelServices.GreyNoise, Ip, HttpStatusCode.NotFound, ReadOnlyMemory<byte>.Empty, DateTimeOffset.UtcNow).Verdict);
        Assert.Equal(IntelVerdicts.Unknown, IntelProviders.Parse(IntelServices.VirusTotal, Ip, HttpStatusCode.OK, Json("not json"), DateTimeOffset.UtcNow).Verdict);
        Assert.Equal(IntelVerdicts.Unknown, IntelProviders.Parse(IntelServices.VirusTotal, Ip, HttpStatusCode.TooManyRequests, ReadOnlyMemory<byte>.Empty, DateTimeOffset.UtcNow).Verdict);
        Assert.False(IntelStatus.IsCacheable(HttpStatusCode.TooManyRequests));
        Assert.True(IntelStatus.StopsService(HttpStatusCode.Unauthorized));
    }

    [Fact]
    public void RequestsUseFixedHostsAndTheRightHeader()
    {
        using var vt = IntelProviders.BuildRequest(IntelServices.VirusTotal, new IntelIndicator(IntelKinds.Domain, "evil.example"), "k1");
        Assert.Equal("https://www.virustotal.com/api/v3/domains/evil.example", vt.RequestUri!.ToString());
        Assert.True(vt.Headers.Contains("x-apikey"));
        using var abuse = IntelProviders.BuildRequest(IntelServices.AbuseIpDb, Ip, "k2");
        Assert.Equal("api.abuseipdb.com", abuse.RequestUri!.Host);
        Assert.True(abuse.Headers.Contains("Key"));
        Assert.Throws<ArgumentException>(() => IntelProviders.BuildRequest(IntelServices.AbuseIpDb, new IntelIndicator(IntelKinds.Hash, new string('a', 64)), "k"));
    }

    [Fact]
    public async Task ClientRejectsOversizedResponses()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[IntelLookupClient.MaximumResponseBytes + 1]) });
        var client = new IntelLookupClient(new HttpClient(handler));
        await Assert.ThrowsAsync<InvalidDataException>(() => client.LookupAsync(IntelServices.GreyNoise, Ip, "k", CancellationToken.None));
    }
}

public sealed class IntelStorageTests
{
    [Fact]
    public void KeysAreEncryptedAndNeverStoredInPlaintext()
    {
        var path = Path.Combine(Path.GetTempPath(), $"downpour-keys-{Guid.NewGuid():N}.json");
        try
        {
            var store = new IntelKeyStore(path);
            Assert.True(store.Set(IntelServices.VirusTotal, "SUPERSECRETKEY123"));
            Assert.DoesNotContain("SUPERSECRETKEY123", File.ReadAllText(path));
            Assert.Equal("SUPERSECRETKEY123", new IntelKeyStore(path).Get(IntelServices.VirusTotal));
            Assert.Equal([IntelServices.VirusTotal], store.ConfiguredServices);
            Assert.False(store.Set(IntelServices.VirusTotal, "has space"));
            Assert.False(store.Set("Shodan", "abc"));
            Assert.True(store.Set(IntelServices.VirusTotal, null));
            Assert.Empty(store.ConfiguredServices);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SettingsPipeAcceptsSecretsOnlyForApiKeys()
    {
        static SensorSettingRequest? Parse(string json) => SensorSettingsPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(json));
        var id = Guid.NewGuid().ToString("D");
        Assert.NotNull(Parse($$"""{"schemaVersion":1,"requestId":"{{id}}","key":"apiKey.VirusTotal","value":true,"secret":"abc"}"""));
        Assert.NotNull(Parse($$"""{"schemaVersion":1,"requestId":"{{id}}","key":"apiKey.VirusTotal","value":false}"""));
        Assert.Null(Parse($$"""{"schemaVersion":1,"requestId":"{{id}}","key":"apiKey.VirusTotal","value":true}"""));
        Assert.Null(Parse($$"""{"schemaVersion":1,"requestId":"{{id}}","key":"intelLookups","value":true,"secret":"abc"}"""));
        Assert.Null(Parse($$"""{"schemaVersion":1,"requestId":"{{id}}","key":"apiKey.Shodan","value":true,"secret":"abc"}"""));
    }

    [Fact]
    public void RateLimiterEnforcesPerMinuteLimit()
    {
        var limiter = new IntelRateLimiter();
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(4, Enumerable.Range(0, 10).Count(_ => limiter.TryAcquire(IntelServices.VirusTotal, now)));
        Assert.True(limiter.TryAcquire(IntelServices.VirusTotal, now.AddMinutes(1.1)));
    }
}

public sealed class IntelWorkerTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"downpour-intel-{Guid.NewGuid():N}");
    private SecurityAlertRepository _alerts = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        _alerts = new SecurityAlertRepository(Path.Combine(_directory, "alerts.db"));
        await _alerts.InitializeAsync();
    }

    public Task DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task LooksUpPublicIndicatorsOnceRaisesFindingsAndLogsWithoutValues()
    {
        await _alerts.IngestFindingsAsync(
        [
            SecurityFindingMapper.Create(SecurityFindingCatalog.RemoteAccess, "Remote access", "HIGH", "T1571", "nc.exe is connected to 8.8.4.4:4444 (Metasploit)", "port:x"),
            SecurityFindingMapper.Create(SecurityFindingCatalog.RemoteAccess, "Remote access", "HIGH", "T1571", "nc.exe is connected to 192.168.1.9:4444", "port:y"),
        ], DateTimeOffset.UtcNow);

        var settings = new SensorSettingsStore(Path.Combine(_directory, "settings.json"));
        var keys = new IntelKeyStore(Path.Combine(_directory, "keys.json"));
        keys.Set(IntelServices.AbuseIpDb, "TESTKEY");
        var results = new IntelResultStore(Path.Combine(_directory, "results.json"));
        var requests = new List<HttpRequestMessage>();
        var handler = new FakeHandler(request =>
        {
            requests.Add(request);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"data":{"abuseConfidenceScore":95,"totalReports":40}}""") };
        });
        var worker = new IntelLookupWorker(settings, keys, results, _alerts, NullLogger<IntelLookupWorker>.Instance) { Client = new IntelLookupClient(new HttpClient(handler)) };

        Assert.Equal(1, await worker.RunOnceAsync(CancellationToken.None));
        var request = Assert.Single(requests);
        Assert.Contains("ipAddress=8.8.4.4", request.RequestUri!.Query);
        Assert.Equal("TESTKEY", request.Headers.GetValues("Key").Single());

        var snapshot = await _alerts.ReadSnapshotAsync();
        Assert.Contains(snapshot.Alerts, alert => alert.LogName == SecurityFindingCatalog.Intel && alert.Severity == "HIGH" && alert.Title.Contains("8.8.4.4"));
        Assert.DoesNotContain("8.8.4.4", string.Concat(results.RecentLookups(10).Select(record => record.ToString())));

        // Cached: a second run sends nothing.
        Assert.Equal(0, await worker.RunOnceAsync(CancellationToken.None));
        Assert.Single(requests);
    }

    [Fact]
    public async Task SendsNothingWhenOffOrWithoutKeys()
    {
        var settings = new SensorSettingsStore(Path.Combine(_directory, "settings.json"));
        var keys = new IntelKeyStore(Path.Combine(_directory, "keys.json"));
        var results = new IntelResultStore(Path.Combine(_directory, "results.json"));
        var handler = new FakeHandler(_ => throw new InvalidOperationException("No request expected."));
        var worker = new IntelLookupWorker(settings, keys, results, _alerts, NullLogger<IntelLookupWorker>.Instance) { Client = new IntelLookupClient(new HttpClient(handler)) };
        Assert.Equal(0, await worker.RunOnceAsync(CancellationToken.None));
        Assert.Contains("No API keys", results.LastRunStatus);

        keys.Set(IntelServices.VirusTotal, "K");
        settings.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.IntelLookups, false));
        Assert.Equal(0, await worker.RunOnceAsync(CancellationToken.None));
        Assert.Contains("off", results.LastRunStatus);
    }
}

internal sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = respond(request);
        response.RequestMessage = request;
        return Task.FromResult(response);
    }
}
