using System.Text;
using System.Text.Json;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatFeedBreadthTests
{
    private static readonly string Md5 = new('a', 32);
    private static readonly string Sha1 = new('b', 40);
    private static readonly string Sha256 = new('c', 64);

    private static ThreatFeedDefinition Feed(string id) => ThreatFeedCatalog.Find(id) ?? throw new InvalidOperationException(id);

    private static ParsedThreatFeed Parse(ThreatFeedDefinition feed, string text) =>
        ThreatFeedParser.Parse(feed, Encoding.UTF8.GetBytes(text));

    public static IEnumerable<object[]> BudgetFixtures()
    {
        yield return ["threatview-domain", "first.example\nsecond.example", "first.example\nsecond.example\nthird.example"];
        yield return ["urlhaus", "0.0.0.0 first.example\n0.0.0.0 second.example", "0.0.0.0 first.example\n0.0.0.0 second.example\n0.0.0.0 third.example"];
        yield return ["threatview-url", "https://first.example/a\nftp://second.example/b", "https://first.example/a\nftp://second.example/b\nhttps://third.example/c"];
        yield return ["digitalside-hash", HashDocument(new { md5 = Md5, sha1 = Sha1 }), HashDocument(new { md5 = Md5, sha1 = Sha1, sha256 = Sha256 })];
    }

    [Theory]
    [MemberData(nameof(BudgetFixtures))]
    public void SourceBudgetAcceptsExactlyTheLimitAndRejectsExcessWithoutTruncation(string id, string exact, string excess)
    {
        var feed = Feed(id) with { IndicatorLimit = 2 };

        Assert.Equal(2, Parse(feed, exact).Indicators.Count);
        Assert.Throws<InvalidDataException>(() => Parse(feed, excess));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(3_000_001)]
    [InlineData(int.MaxValue)]
    public void InvalidSourceBudgetsAreRejectedBeforeParsing(int budget)
    {
        var feed = Feed("threatview-domain") with { IndicatorLimit = budget };

        Assert.Throws<InvalidDataException>(() => Parse(feed, "first.example"));
    }

    [Fact]
    public void ExpandedDomainSourceCanReadBeyondTheFormerGlobalBudget()
    {
        var feed = Feed("threatview-domain");
        var count = ThreatFeedParser.MaximumIndicators + 1;
        var content = new StringBuilder(count * 20);
        for (var i = 0; i < count; i++) content.Append("node").Append(i).Append(".example\n");

        var parsed = Parse(feed, content.ToString());

        Assert.Equal(count, parsed.Indicators.Count);
        Assert.Equal($"node{count - 1}.example", parsed.Indicators[^1].Value);
        Assert.Equal(0, parsed.RejectedLines);
    }

    [Fact]
    public void StreamingLinesIgnoreCommentsAndBlankLinesWithoutUsingTheDataBudget()
    {
        var feed = Feed("threatview-domain") with { IndicatorLimit = 1 };
        var content = string.Concat(Enumerable.Repeat("# source metadata\r\n; comment\n \n", 20)) + "  FIRST.EXAMPLE.  \n";

        var parsed = Parse(feed, content);

        Assert.Equal("first.example", Assert.Single(parsed.Indicators).Value);
        Assert.Equal(0, parsed.RejectedLines);
    }

    [Fact]
    public void FilteredLinesStillHaveAnInputBudget()
    {
        var feed = Feed("threatview-domain") with { IndicatorLimit = 1 };

        Assert.Throws<InvalidDataException>(() => Parse(feed, "github.com\ngoogle.com\nfirst.example"));
    }

    [Fact]
    public void FtpUrlsRetainOnlyNormalizedHostsAndDeduplicateAcrossSchemes()
    {
        const string content = "ftp://user:secret@PAYLOAD.EXAMPLE:2121/path/file.bin?token=private#fragment\nhttps://payload.example/other\nftp://next.example/file";

        var parsed = Parse(Feed("threatview-url"), content);

        Assert.Equal(["payload.example", "next.example"], parsed.Indicators.Select(i => i.Value).ToArray());
        Assert.All(parsed.Indicators, i =>
        {
            Assert.Equal(IndicatorType.Domain, i.Type);
            Assert.Equal(Feed("threatview-url").DefaultLabel, i.Label);
        });
        Assert.Equal(0, parsed.RejectedLines);
    }

    [Theory]
    [InlineData("file://payload.example/path")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/plain,payload.example")]
    [InlineData("smb://payload.example/share")]
    [InlineData("payload.example/path")]
    public void UrlFeedsRejectUnsupportedSchemesAndRelativeUrls(string unsupported)
    {
        var parsed = Parse(Feed("threatview-url"), "ftp://allowed.example/file\n" + unsupported);

        Assert.Equal("allowed.example", Assert.Single(parsed.Indicators).Value);
        Assert.Equal(1, parsed.RejectedLines);
    }

    [Fact]
    public void FtpUrlsExcludeSharedPlatformsButKeepCustomerSpecificHosting()
    {
        const string content = "ftp://github.com/owner/repo/file\nftp://docs.google.com/file\nftp://vercel.app/file\nftp://customer.vercel.app/file";

        var parsed = Parse(Feed("threatview-url"), content);

        Assert.Equal("customer.vercel.app", Assert.Single(parsed.Indicators).Value);
        Assert.Equal(0, parsed.RejectedLines);
    }

    [Fact]
    public void HistoricalHashFeedNormalizesDeduplicatesAndIgnoresNetworkFields()
    {
        var content = JsonSerializer.Serialize(new
        {
            generatedAt = "2024-10-18 09:08:16",
            lookup = new Dictionary<string, object>
            {
                ["first"] = new { md5 = Md5.ToUpperInvariant(), sha1 = Sha1, sha256 = Sha256, url = new[] { "http://old.example/payload" }, ip = "8.8.4.4", domain = "old.example" },
                ["second"] = new { md5 = Md5, sha1 = Sha1.ToUpperInvariant(), sha256 = Sha256.ToUpperInvariant() },
            },
        });

        var parsed = Parse(Feed("digitalside-hash") with { IndicatorLimit = 3 }, content);

        Assert.Equal(3, parsed.Indicators.Count);
        Assert.Contains(parsed.Indicators, i => i.Type == IndicatorType.Md5 && i.Value == Md5);
        Assert.Contains(parsed.Indicators, i => i.Type == IndicatorType.Sha1 && i.Value == Sha1);
        Assert.Contains(parsed.Indicators, i => i.Type == IndicatorType.Sha256 && i.Value == Sha256);
        Assert.DoesNotContain(parsed.Indicators, i => i.Type is IndicatorType.Domain or IndicatorType.Ip);
        Assert.Equal(0, parsed.RejectedLines);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"lookup\":[]}")]
    [InlineData("{\"lookup\":null}")]
    [InlineData("{\"lookup\":\"not an object\"}")]
    [InlineData("{\"lookup\":{\"first\":{\"url\":[\"http://old.example/file\"]}}}")]
    [InlineData("{\"lookup\":{\"first\":{\"md5\":null}}}")]
    [InlineData("{\"lookup\":{\"first\":[]}}")]
    [InlineData("{\"lookup\":")]
    public void HistoricalHashFeedRejectsMissingOrMalformedHashSchema(string content)
    {
        Assert.Throws<InvalidDataException>(() => Parse(Feed("digitalside-hash"), content));
    }

    [Fact]
    public void HistoricalHashFeedDoesNotReclassifyWrongAlgorithmsOrTypedValues()
    {
        var content = JsonSerializer.Serialize(new
        {
            lookup = new Dictionary<string, object>
            {
                ["valid"] = new { sha256 = Sha256 },
                ["wrongAlgorithms"] = new { md5 = Sha1, sha1 = Sha256, sha256 = Md5 },
                ["wrongTypes"] = new { md5 = new[] { Md5 }, sha1 = true, sha256 = 123 },
                ["wrongRecord"] = 42,
                ["networkInHash"] = new { md5 = "payload.example", sha1 = "8.8.8.8", sha256 = "8.8.8.0/24" },
            },
        });

        var parsed = Parse(Feed("digitalside-hash"), content);

        Assert.Equal(Sha256, Assert.Single(parsed.Indicators).Value);
        Assert.Equal(10, parsed.RejectedLines);
    }

    [Fact]
    public void MostlyMalformedHistoricalHashRecordsRejectTheEntirePayload()
    {
        var entries = Enumerable.Range(0, 25).ToDictionary(i => i.ToString(), i => (object)new { sha256 = i == 0 ? Sha256 : "wrong" });
        var content = JsonSerializer.Serialize(new { lookup = entries });

        Assert.Throws<InvalidDataException>(() => Parse(Feed("digitalside-hash"), content));
    }

    [Fact]
    public void NewHashSourcesRetainSeparateProvenanceInLocalLookup()
    {
        var historical = Feed("digitalside-hash");
        var threatview = Feed("threatview-md5");
        var index = ThreatIndex.Build([
            (historical, Parse(historical, HashDocument(new { md5 = Md5 }))),
            (threatview, Parse(threatview, Md5)),
        ]);

        var hits = index.Lookup(new ThreatIndicator(IndicatorType.Md5, Md5, ""));

        Assert.Equal(1, index.IndicatorCount);
        Assert.Equal(2, hits.Count);
        Assert.Contains(hits, h => h.Feed.Id == historical.Id && h.Label == historical.DefaultLabel);
        Assert.Contains(hits, h => h.Feed.Id == threatview.Id && h.Label == threatview.DefaultLabel);
    }

    private static string HashDocument(object sample) => JsonSerializer.Serialize(new { lookup = new Dictionary<string, object> { ["first"] = sample } });
}
