using System.IO.Compression;
using System.Net;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class ThreatDatabaseTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "downpour_threatdb_" + Guid.NewGuid().ToString("N"));

    public ThreatDatabaseTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        try { Directory.Delete(_folder, true); } catch (IOException) { }
    }

    private static ThreatFeedDefinition Feed(string id) => ThreatFeedCatalog.Find(id)!;
    private static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);

    [Theory]
    [InlineData("1.2.3.4", IndicatorType.Ip, "1.2.3.4")]
    [InlineData("2001:db8::1", IndicatorType.Ip, "2001:db8::1")]
    [InlineData("5.6.0.0/16", IndicatorType.Network, "5.6.0.0/16")]
    [InlineData("9.9.9.9/32", IndicatorType.Ip, "9.9.9.9")]
    [InlineData("Evil.Example.COM.", IndicatorType.Domain, "evil.example.com")]
    [InlineData("44D88612FEA8A8F36DE82E1278ABB02F", IndicatorType.Md5, "44d88612fea8a8f36de82e1278abb02f")]
    [InlineData("3395856ce81f2b7382dee72602f798b642f14140", IndicatorType.Sha1, "3395856ce81f2b7382dee72602f798b642f14140")]
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IndicatorType.Sha256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")]
    public void ClassifiesAndNormalizesIndicators(string raw, IndicatorType type, string value)
    {
        Assert.True(ThreatFeedParser.TryClassify(raw, out var indicator));
        Assert.Equal(type, indicator.Type);
        Assert.Equal(value, indicator.Value);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("localhost")]
    [InlineData("1.2.3")]
    [InlineData("-bad-.example")]
    [InlineData("abc123")]
    [InlineData("not a domain.com")]
    [InlineData("")]
    public void RejectsMalformedIndicators(string raw) => Assert.False(ThreatFeedParser.TryClassify(raw, out _));

    [Fact]
    public void NeverIndexesPrivateOrReservedSpace()
    {
        var parsed = ThreatFeedParser.Parse(Feed("firehol-level1"), Utf8("# header\n10.0.0.0/8\n192.168.0.0/16\n127.0.0.0/8\n0.0.0.0/8\n5.6.0.0/16\n"));
        var index = ThreatIndex.Build([(Feed("firehol-level1"), parsed)]);
        Assert.Empty(Lookup(index, "10.1.2.3"));
        Assert.Empty(Lookup(index, "192.168.1.10"));
        Assert.Single(Lookup(index, "5.6.7.8"));
    }

    [Fact]
    public void ParsesHostsFilesAndMatchesParentDomains()
    {
        var parsed = ThreatFeedParser.Parse(Feed("urlhaus"), Utf8("# URLhaus\n127.0.0.1\tmalware.example\n127.0.0.1\tlocalhost\n"));
        var index = ThreatIndex.Build([(Feed("urlhaus"), parsed)]);
        Assert.Single(Lookup(index, "cdn.malware.example"));
        Assert.Single(Lookup(index, "malware.example"));
        Assert.False(ThreatFeedParser.TryClassify("example", out _));
        Assert.Empty(Lookup(index, "notmalware.example"));
    }

    [Fact]
    public void UrlFeedsSkipFirstPartyPlatformsButKeepUserHostedSites()
    {
        var parsed = ThreatFeedParser.Parse(Feed("openphish"), Utf8(
            "https://docs.google.com/forms/d/phish\nhttps://raw.githubusercontent.com/x/y/main/a\nhttps://bank-login.vercel.app/\nhttps://vercel.app/\nhttp://phish.example/login\n"));
        var values = parsed.Indicators.Select(i => i.Value).ToArray();
        Assert.Contains("bank-login.vercel.app", values);
        Assert.Contains("phish.example", values);
        Assert.DoesNotContain("docs.google.com", values);
        Assert.DoesNotContain("raw.githubusercontent.com", values);
        Assert.DoesNotContain("vercel.app", values);
    }

    [Fact]
    public void DomainFeedsSkipSharedSdkHostsButKeepCustomerBuckets()
    {
        var parsed = ThreatFeedParser.Parse(Feed("stalkerware"), Utf8(
            "alog.umeng.com\nb.appjiagu.com\nspy-app-uploads.s3.amazonaws.com\ns3.amazonaws.com\nd1abc.cloudfront.net\nthetruthspy.com\n"));
        var values = parsed.Indicators.Select(i => i.Value).ToArray();
        Assert.Equal(["spy-app-uploads.s3.amazonaws.com", "d1abc.cloudfront.net", "thetruthspy.com"], values);
    }

    [Fact]
    public void ParsesFeodoCsvWithMalwareFamily()
    {
        var parsed = ThreatFeedParser.Parse(Feed("feodo"), Utf8(
            "# Feodo\n\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\"2025-12-30 13:56:31\",\"50.16.16.211\",\"443\",\"online\",\"2026-03-12\",\"QakBot\"\n"));
        var indicator = Assert.Single(parsed.Indicators);
        Assert.Equal("50.16.16.211", indicator.Value);
        Assert.Equal("Botnet C2 (QakBot)", indicator.Label);
    }

    [Fact]
    public void ParsesSpamhausJsonLinesAndSkipsMetadata()
    {
        var parsed = ThreatFeedParser.Parse(Feed("spamhaus-drop"), Utf8(
            "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n{\"type\":\"metadata\",\"timestamp\":1791393242,\"records\":1}\n"));
        Assert.Equal("1.10.16.0/20", Assert.Single(parsed.Indicators).Value);
    }

    [Fact]
    public void ParsesThreatFoxPortsUrlsHashesAndSkipsLowConfidence()
    {
        var json = """
        {"1":[{"ioc_value":"45.9.8.7:4444","ioc_type":"ip:port","threat_type":"botnet_cc","malware_printable":"AsyncRAT","confidence_level":100}],
         "2":[{"ioc_value":"https://drop.example/a.exe","ioc_type":"url","threat_type":"payload_delivery","malware_printable":"Lumma","confidence_level":75}],
         "3":[{"ioc_value":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","ioc_type":"sha256_hash","threat_type":"payload","malware_printable":"Unknown malware","confidence_level":90}],
         "4":[{"ioc_value":"maybe.example","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"X","confidence_level":25}],
         "5":[{"ioc_value":"https://docs.google.com/x","ioc_type":"url","threat_type":"payload_delivery","malware_printable":"Y","confidence_level":100}]}
        """;
        var parsed = ThreatFeedParser.Parse(Feed("threatfox"), Utf8(json));
        var byValue = parsed.Indicators.ToDictionary(i => i.Value);
        Assert.Equal("Malware C2 (AsyncRAT)", byValue["45.9.8.7"].Label);
        Assert.Equal("Malware delivery (Lumma)", byValue["drop.example"].Label);
        Assert.Equal("Malware sample", byValue["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"].Label);
        Assert.False(byValue.ContainsKey("maybe.example"));
        Assert.False(byValue.ContainsKey("docs.google.com"));
    }

    [Fact]
    public void ParsesLolDriversHashesWithCategory()
    {
        var json = """
        [{"Category":"malicious","Tags":["poortry.sys"],"KnownVulnerableSamples":[{"OriginalFilename":"poortry.sys","SHA256":"090d409f86430e078694e621ad0bd5e458d32aa727f0eb99bda3961577df8d49","MD5":"41046ce853788277da0d7e8c4e0a3123"}]},
         {"Category":"vulnerable driver","Tags":["RTCore64.sys"],"KnownVulnerableSamples":[{"Filename":"RTCore64.sys","SHA1":"f6f11ad2cd2b0cf95ed42324876bee1d83e01775"}]}]
        """;
        var parsed = ThreatFeedParser.Parse(Feed("loldrivers"), Utf8(json));
        Assert.Equal(3, parsed.Indicators.Count);
        Assert.Contains(parsed.Indicators, i => i.Type == IndicatorType.Sha256 && i.Label == "Malicious driver: poortry.sys");
        Assert.Contains(parsed.Indicators, i => i.Type == IndicatorType.Sha1 && i.Label == "Vulnerable driver: RTCore64.sys");
    }

    [Fact]
    public void ParsesLolbasNamesCategoriesAndTechniques()
    {
        var json = """[{"Name":"Certutil.exe","Commands":[{"Category":"Download","MitreID":"T1105"},{"Category":"Decode","MitreID":"T1140"}]},{"Name":"../../evil","Commands":[]}]""";
        var parsed = ThreatFeedParser.Parse(Feed("lolbas"), Utf8(json));
        var lolbin = Assert.Single(parsed.Lolbins);
        Assert.Equal("certutil.exe", lolbin.Name);
        Assert.Equal("Decode, Download", lolbin.Categories);
        Assert.Equal("T1105, T1140", lolbin.Techniques);
        Assert.NotNull(ThreatIndex.Build([(Feed("lolbas"), parsed)]).Lolbin("CERTUTIL.EXE"));
    }

    [Fact]
    public void RejectsFeedsWhoseFormatChanged()
    {
        var junk = string.Join('\n', Enumerable.Range(0, 50).Select(i => $"<html>row {i}</html>")) + "\n1.2.3.4\n";
        Assert.Throws<InvalidDataException>(() => ThreatFeedParser.Parse(Feed("cins"), Utf8(junk)));
        Assert.Throws<InvalidDataException>(() => ThreatFeedParser.Parse(Feed("cins"), Utf8("# only comments\n")));
        Assert.Throws<InvalidDataException>(() => ThreatFeedParser.Parse(Feed("threatfox"), Utf8("[1,2,3]")));
    }

    [Fact]
    public void IndexKeepsOneHitPerFeedAndCombinesFeeds()
    {
        var a = ThreatFeedParser.Parse(Feed("cins"), Utf8("8.8.4.4\n8.8.4.4\n"));
        var b = ThreatFeedParser.Parse(Feed("ipsum"), Utf8("8.8.4.4\n"));
        var hits = Lookup(ThreatIndex.Build([(Feed("cins"), a), (Feed("ipsum"), b)]), "8.8.4.4");
        Assert.Equal(["cins", "ipsum"], hits.Select(h => h.Feed.Id).Order().ToArray());
    }

    [Fact]
    public void CacheRoundTripsAndDetectsCorruptionAndExpiry()
    {
        var feed = Feed("tor-exit");
        var cache = new ThreatFeedCache(_folder);
        var now = DateTimeOffset.UtcNow;
        var payload = Utf8("1.2.3.4\n5.6.7.8\n");
        cache.Write(feed, payload, now);
        var read = cache.TryRead(feed, now);
        Assert.NotNull(read);
        Assert.Equal(payload, read.Value.Payload);
        Assert.Null(cache.TryRead(feed, now + ThreatFeedCache.MaximumAge + TimeSpan.FromHours(1)));

        var bytes = File.ReadAllBytes(cache.PathFor(feed));
        bytes[^1] ^= 0x01;
        File.WriteAllBytes(cache.PathFor(feed), bytes);
        Assert.Throws<InvalidDataException>(() => cache.TryRead(feed, now));

        Assert.Throws<InvalidDataException>(() => cache.Write(feed, Utf8("<html>nope</html>\n"), now));
    }

    private sealed class StubHandler(HttpStatusCode status, byte[] body, string? location = null) : HttpMessageHandler
    {
        public Uri? Requested { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requested = request.RequestUri;
            var response = new HttpResponseMessage(status) { Content = new ByteArrayContent(body), RequestMessage = request };
            if (location is not null) response.Headers.Location = new Uri(location);
            return Task.FromResult(response);
        }
    }

    [Fact]
    public async Task DownloaderRefusesRedirectsOversizeAndUncataloguedFeeds()
    {
        var feed = Feed("tor-exit");
        var redirect = new ThreatFeedDownloader(new HttpClient(new StubHandler(HttpStatusCode.Found, [], "https://elsewhere.example/list")));
        await Assert.ThrowsAsync<HttpRequestException>(() => redirect.FetchAsync(feed, default));

        var huge = new ThreatFeedDownloader(new HttpClient(new StubHandler(HttpStatusCode.OK, new byte[feed.MaximumBytes + 1])));
        await Assert.ThrowsAsync<InvalidDataException>(() => huge.FetchAsync(feed, default));

        var handler = new StubHandler(HttpStatusCode.OK, Utf8("1.2.3.4\n"));
        var ok = new ThreatFeedDownloader(new HttpClient(handler));
        Assert.Equal(Utf8("1.2.3.4\n"), await ok.FetchAsync(feed, default));
        Assert.Equal(feed.Url, handler.Requested!.ToString());

        await Assert.ThrowsAsync<InvalidOperationException>(() => ok.FetchAsync(feed with { Url = "https://evil.example/list" }, default));
    }

    private static byte[] OriginTable()
    {
        var rows = new StringBuilder();
        rows.Append("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n");
        for (var i = 0; i < 1100; i++) rows.Append($"2.{i / 256}.{i % 256}.0\t2.{i / 256}.{i % 256}.255\t{64512 + i % 100}\tGB\tEXAMPLE-NET {i % 100}\n");
        rows.Append("2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n");
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(Utf8(rows.ToString()));
        return output.ToArray();
    }

    [Fact]
    public void IpOriginLooksUpCountryAndNetworkOffline()
    {
        var parsed = ThreatFeedParser.Parse(Feed("ip-origin"), OriginTable());
        var origins = parsed.Origins!;
        Assert.Equal(1102, origins.Ranges);
        var cloudflare = origins.Lookup(IPAddress.Parse("1.0.0.1"))!;
        Assert.Equal(("US", 13335, "CLOUDFLARENET"), (cloudflare.CountryCode, cloudflare.Asn, cloudflare.Network));
        Assert.Equal("GB", origins.Lookup(IPAddress.Parse("2.1.5.9"))!.CountryCode);
        Assert.Equal(15169, origins.Lookup(IPAddress.Parse("2001:4860:4860::8888"))!.Asn);
        Assert.Null(origins.Lookup(IPAddress.Parse("1.0.2.1"))!.Asn); // not routed
        Assert.Null(origins.Lookup(IPAddress.Parse("192.168.1.1")));    // private: never looked up
        Assert.Equal("United Kingdom", IpOriginDatabase.CountryName("GB"));
    }

    [Fact]
    public void IpOriginRejectsUnsortedOrNonGzipData()
    {
        Assert.Throws<InvalidDataException>(() => IpOriginDatabase.Parse(Utf8("1.0.0.0\t1.0.0.255\t1\tUS\tX\n")));
        var rows = new StringBuilder();
        for (var i = 1100; i > 0; i--) rows.Append($"3.{i / 256}.{i % 256}.0\t3.{i / 256}.{i % 256}.255\t1\tUS\tX\n");
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(Utf8(rows.ToString()));
        Assert.Throws<InvalidDataException>(() => IpOriginDatabase.Parse(output.ToArray()));
    }

    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\tcpip.sys", @"\System32\drivers\tcpip.sys")]
    [InlineData(@"\??\C:\Program Files\Vendor\x.sys", @"C:\Program Files\Vendor\x.sys")]
    [InlineData(@"System32\DRIVERS\wd.sys", @"\System32\DRIVERS\wd.sys")]
    public void NormalizesKernelDriverPaths(string image, string expectedSuffix)
    {
        var path = ThreatDatabaseService.DriverPath(image);
        Assert.NotNull(path);
        Assert.EndsWith(expectedSuffix, path, StringComparison.OrdinalIgnoreCase);
        Assert.True(Path.IsPathFullyQualified(path));
    }

    [Fact]
    public void DriverInventoryNamesDriversEvenWhenWindowsHidesKernelAddresses()
    {
        // Windows 11 24H2+ zeroes kernel image bases for standard accounts; the provider must still name running drivers.
        var snapshot = new DriverInventoryProvider().Capture();
        if (snapshot.DriverCount == 0) return;
        Assert.NotEmpty(snapshot.Drivers);
        Assert.Contains(snapshot.Drivers, d => d.Name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(@"\??\C:\Windows\..\evil.sys")]
    [InlineData(@"relative\x.sys")]
    public void RejectsUnsafeDriverPaths(string image) => Assert.Null(ThreatDatabaseService.DriverPath(image));

    private ThreatDatabaseService CreateService(string pipe) => new(
        new SecurityAlertRepository(Path.Combine(_folder, "alerts.db")),
        new SensorSettingsStore(Path.Combine(_folder, "settings.json")),
        new DnsInventoryProvider(Path.Combine(_folder, "dns.json")),
        new DriverInventoryProvider(),
        NullLogger<ThreatDatabaseService>.Instance,
        new ThreatFeedCache(Path.Combine(_folder, "cache")),
        new ThreatFeedDownloader(new HttpClient(new StubHandler(HttpStatusCode.ServiceUnavailable, []))),
        pipe);

    [Fact]
    public async Task ServiceLooksUpFromSavedFeedsAndRejectsBadRequests()
    {
        var cache = new ThreatFeedCache(Path.Combine(_folder, "cache"));
        cache.Write(Feed("stalkerware"), Utf8("spy-server.example\n"), DateTimeOffset.UtcNow);
        cache.Write(Feed("ip-origin"), OriginTable(), DateTimeOffset.UtcNow);
        using var service = CreateService("Downpour.Test.ThreatDb." + Guid.NewGuid().ToString("N"));
        service.LoadCaches();

        var hit = await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Lookup, "https://node1.spy-server.example/upload"), default);
        Assert.True(hit.Accepted);
        Assert.Equal("domain", hit.LookupKind);
        Assert.Equal("stalkerware", Assert.Single(hit.LookupHits!).FeedId);

        var origin = await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Lookup, "1.0.0.9"), default);
        Assert.Equal("CLOUDFLARENET", origin.LookupOrigin!.Network);

        Assert.False((await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Lookup, "rm -rf /"), default)).Accepted);
        Assert.False((await service.HandleAsync(new ThreatDatabaseRequest(2, ThreatDatabaseOperations.Snapshot, null), default)).Accepted);
        Assert.False((await service.HandleAsync(new ThreatDatabaseRequest(1, "delete", null), default)).Accepted);

        var browse = await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Browse, "SPY", "stalkerware"), default);
        Assert.Equal(1, browse.BrowseTotal);
        Assert.Equal("spy-server.example", Assert.Single(browse.Browse!).Value);
        Assert.False((await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Browse, null, "../etc"), default)).Accepted);
        Assert.Equal(0, (await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Browse, null, "cins"), default)).BrowseTotal);

        var snapshot = (await service.HandleAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Snapshot, null), default)).Snapshot!;
        Assert.True(ThreatDatabaseClient.IsValid(snapshot));
        Assert.Equal(ThreatFeedStates.Current, snapshot.Feeds.Single(f => f.Id == "stalkerware").State);
        Assert.Equal(ThreatFeedStates.NotLoaded, snapshot.Feeds.Single(f => f.Id == "cins").State);
    }

    [Fact]
    public async Task FailedDownloadsAreReportedNotHidden()
    {
        using var service = CreateService("Downpour.Test.ThreatDb." + Guid.NewGuid().ToString("N"));
        service.LoadCaches();
        Assert.Equal(0, await service.RefreshDueAsync(force: false, default));
        var snapshot = service.Snapshot();
        Assert.All(snapshot.Feeds, f => Assert.Equal(ThreatFeedStates.Failed, f.State));
        Assert.All(snapshot.Feeds, f => Assert.Contains("503", f.Error));
    }

    [Fact]
    public async Task PipeServesSnapshotAndLookups()
    {
        var pipe = "Downpour.Test.ThreatDb." + Guid.NewGuid().ToString("N");
        new ThreatFeedCache(Path.Combine(_folder, "cache")).Write(Feed("feodo"), Utf8("# x\n\"a\",\"50.16.16.211\",\"443\",\"online\",\"b\",\"QakBot\"\n"), DateTimeOffset.UtcNow);
        using var service = CreateService(pipe);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await service.StartAsync(cts.Token);
        try
        {
            var client = new ThreatDatabaseClient(pipe);
            ThreatDatabaseResponse? lookup = null;
            for (var attempt = 0; attempt < 50 && lookup?.LookupHits is not { Count: > 0 }; attempt++)
            {
                lookup = await client.LookupAsync("50.16.16.211", cts.Token);
                if (lookup?.LookupHits is not { Count: > 0 }) await Task.Delay(100, cts.Token);
            }
            Assert.Equal("Botnet C2 (QakBot)", Assert.Single(lookup!.LookupHits!).Label);
            var snapshot = await client.GetSnapshotAsync(cts.Token);
            Assert.NotNull(snapshot?.Snapshot);
            Assert.Null(await client.LookupAsync(new string('a', 3000), cts.Token));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }

    private static IReadOnlyList<(ThreatFeedDefinition Feed, string Label)> Lookup(ThreatIndex index, string value)
    {
        Assert.True(ThreatFeedParser.TryClassify(value, out var indicator));
        return index.Lookup(indicator);
    }
}
