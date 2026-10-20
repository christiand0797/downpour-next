using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatIndexCompactTests
{
    private static ThreatFeedDefinition Feed(string id) => ThreatFeedCatalog.Find(id)!;
    private static ParsedThreatFeed Parsed(params ThreatIndicator[] indicators) => new(indicators, 0, []);
    private static ThreatIndicator Domain(string value, string label) => new(IndicatorType.Domain, value, label);

    [Fact]
    public void SortingKeepsFirstLabelPerFeedAndOriginalProvenanceOrder()
    {
        var index = ThreatIndex.Build([
            (Feed("urlhaus"), Parsed(Domain("z.example", "last key"), Domain("shared.example", "first URLhaus"),
                Domain("shared.example", "later URLhaus"), Domain("a.example", "first key"))),
            (Feed("blp-phishing"), Parsed(Domain("shared.example", "phishing"))),
            (Feed("threatview-domain"), Parsed(Domain("shared.example", "reputation"))),
            (Feed("urlhaus"), Parsed(Domain("shared.example", "repeated feed")))
        ]);

        Assert.Equal(3, index.IndicatorCount);
        Assert.Equal(new[] { ("threatview-domain", "reputation"), ("blp-phishing", "phishing"), ("urlhaus", "first URLhaus") },
            index.LookupExact("shared.example").Select(hit => (hit.Feed.Id, hit.Label)).ToArray());
        Assert.Equal("first key", Assert.Single(index.LookupExact("a.example")).Label);
        Assert.Equal("last key", Assert.Single(index.LookupExact("z.example")).Label);
        Assert.Empty(index.LookupExact("absent.example"));
    }

    [Fact]
    public void FullStringComparisonDoesNotConflateSharedPrefixesSuffixesOrCase()
    {
        const string prefix = "very-long-common-prefix-that-exceeds-a-machine-word-";
        var first = prefix + "a.example";
        var second = prefix + "b.example";
        var index = ThreatIndex.Build([(Feed("urlhaus"), Parsed(Domain(first, "first"), Domain(second, "second"),
            Domain("a." + first, "subdomain"), Domain("other.example", "other")))]);

        Assert.Equal("first", Assert.Single(index.LookupExact(first)).Label);
        Assert.Equal("second", Assert.Single(index.LookupExact(second)).Label);
        Assert.Equal("subdomain", Assert.Single(index.LookupExact("a." + first)).Label);
        Assert.Empty(index.LookupExact(prefix + "c.example"));
        Assert.Empty(index.LookupExact(first.ToUpperInvariant())); // Exact lookup expects normalized input.
        Assert.True(ThreatFeedParser.TryClassify(first.ToUpperInvariant(), out var normalized));
        Assert.Equal("first", Assert.Single(index.Lookup(normalized)).Label);
    }

    [Fact]
    public void ParentExpansionPreservesSpecificAndParentEvidenceWithoutMatchingSuffixFragments()
    {
        var index = ThreatIndex.Build([
            (Feed("urlhaus"), Parsed(Domain("evil.example", "parent"), Domain("cdn.evil.example", "specific"))),
            (Feed("blp-phishing"), Parsed(Domain("evil.example", "second source")))
        ]);

        Assert.Equal(new[] { "specific", "second source", "parent" },
            index.Lookup(Domain("cdn.evil.example", "")).Select(hit => hit.Label).ToArray());
        Assert.Equal(new[] { "second source", "parent" },
            index.Lookup(Domain("deep.sub.evil.example", "")).Select(hit => hit.Label).ToArray());
        Assert.Empty(index.Lookup(Domain("notevil.example", "")));
        Assert.Empty(index.Lookup(Domain("evil.example.other", "")));
        Assert.Single(index.LookupExact("cdn.evil.example"));
    }

    [Fact]
    public void ExactIpsNetworksReservedSpaceAndMappedIpv4RetainTheirSemantics()
    {
        var index = ThreatIndex.Build([
            (Feed("cins"), Parsed(new(IndicatorType.Ip, "8.8.4.4", "exact"), new(IndicatorType.Network, "8.8.0.0/16", "same feed range"),
                new(IndicatorType.Ip, "127.0.0.1", "reserved"))),
            (Feed("ipsum"), Parsed(new(IndicatorType.Network, "8.8.4.0/24", "second range"),
                new(IndicatorType.Ip, "2001:4860:4860::8888", "IPv6"))),
            (Feed("firehol-level1"), Parsed(new ThreatIndicator(IndicatorType.Network, "2001:4860::/32", "IPv6 range")))
        ]);

        Assert.Equal(5, index.IndicatorCount);
        Assert.Equal(new[] { "exact", "second range" },
            index.Lookup(new(IndicatorType.Ip, "::ffff:8.8.4.4", "")).Select(hit => hit.Label).ToArray());
        Assert.Equal("exact", Assert.Single(index.LookupExact("8.8.4.4")).Label);
        Assert.Empty(index.LookupExact("8.8.4.3"));
        Assert.Empty(index.Lookup(new(IndicatorType.Ip, "127.0.0.1", "")));
        Assert.Empty(index.LookupExact("127.0.0.1"));
        Assert.Empty(index.Lookup(new(IndicatorType.Ip, "invalid", "")));
        Assert.Equal(new[] { "IPv6", "IPv6 range" },
            index.Lookup(new(IndicatorType.Ip, "2001:4860:4860::8888", "")).Select(hit => hit.Label).ToArray());
    }

    [Fact]
    public void HashAlgorithmsKeepFullValuesAndProvenance()
    {
        var md5 = new string('a', 32);
        var sha1 = new string('a', 40);
        var sha256 = new string('a', 64);
        var index = ThreatIndex.Build([
            (Feed("loldrivers"), Parsed(new(IndicatorType.Md5, md5, "MD5"), new(IndicatorType.Sha1, sha1, "SHA1"),
                new(IndicatorType.Sha256, sha256, "SHA256"))),
            (Feed("digitalside-hash"), Parsed(new ThreatIndicator(IndicatorType.Sha256, sha256, "historical hash")))
        ]);

        Assert.Equal(3, index.IndicatorCount);
        Assert.Equal("MD5", Assert.Single(index.Lookup(new(IndicatorType.Md5, md5, ""))).Label);
        Assert.Equal("SHA1", Assert.Single(index.Lookup(new(IndicatorType.Sha1, sha1, ""))).Label);
        Assert.Equal(new[] { "historical hash", "SHA256" }, index.Lookup(new(IndicatorType.Sha256, sha256, "")).Select(hit => hit.Label).ToArray());
        Assert.Empty(index.LookupExact(new string('a', 63) + "b"));
    }

    [Fact]
    public void UnknownFeedsAreExcludedAndLolbinFirstDefinitionWinsCaseInsensitively()
    {
        var original = new ThreatLolbin("certutil.exe", "Download", "T1105");
        var index = ThreatIndex.Build([
            (Feed("urlhaus") with { Id = "not-catalogued" }, new ParsedThreatFeed([Domain("unknown.example", "ignore")], 0,
                [new ThreatLolbin("unknown.exe", "ignore", "")])),
            (Feed("lolbas"), new ParsedThreatFeed([], 0, [original])),
            (Feed("lolrmm"), new ParsedThreatFeed([], 0, [new ThreatLolbin("CERTUTIL.EXE", "Other", "")]))
        ]);

        Assert.Equal(0, index.IndicatorCount);
        Assert.Equal(1, index.LolbinCount);
        Assert.Equal(original, index.Lolbin("CERTUTIL.EXE"));
        Assert.Null(index.Lolbin("unknown.exe"));
        Assert.Empty(index.LookupExact("unknown.example"));
        Assert.Empty(ThreatIndex.Empty.LookupExact("anything.example"));
    }

    [Fact]
    public void DenseRepeatedValuesCompactWithoutDiscardingEndRowsOrRetainingLaterLabels()
    {
        var indicators = new List<ThreatIndicator>();
        for (var i = 0; i < 12_000; i++)
        {
            indicators.Add(Domain($"node{i % 137:D4}.example", $"first encountered at {i}"));
            indicators.Add(Domain("zz-final.example", "first final"));
        }
        var index = ThreatIndex.Build([(Feed("urlhaus"), new ParsedThreatFeed(indicators, 0, []))]);

        Assert.Equal(138, index.IndicatorCount);
        for (var i = 0; i < 137; i++)
            Assert.Equal($"first encountered at {i}", Assert.Single(index.LookupExact($"node{i:D4}.example")).Label);
        Assert.Equal("first final", Assert.Single(index.LookupExact("zz-final.example")).Label);
    }

    [Fact]
    public void LabelInterningLimitDoesNotLimitIndicatorsOrChangeLabels()
    {
        const int count = 65_540;
        var indicators = Enumerable.Range(0, count).Select(i => Domain($"node{i:D6}.example", $"label {i}")).ToArray();
        var index = ThreatIndex.Build([(Feed("urlhaus"), new ParsedThreatFeed(indicators, 0, []))]);

        Assert.Equal(count, index.IndicatorCount);
        foreach (var i in new[] { 0, 1, 65_534, 65_535, 65_536, count - 1 })
            Assert.Equal($"label {i}", Assert.Single(index.LookupExact($"node{i:D6}.example")).Label);
    }

    [Fact]
    public void PublishedIndexIsIndependentOfInputMutationAndSafeForConcurrentReaders()
    {
        const int count = 12_000;
        var input = Enumerable.Range(0, count).Reverse().Select(i => Domain($"node{i:D5}.example", "listed")).ToArray();
        var index = ThreatIndex.Build([(Feed("urlhaus"), new ParsedThreatFeed(input, 0, []))]);
        Array.Fill(input, Domain("replaced.example", "later input"));

        Parallel.For(0, count, i =>
        {
            Assert.Equal("listed", Assert.Single(index.LookupExact($"node{i:D5}.example")).Label);
            Assert.Empty(index.LookupExact($"missing{i:D5}.example"));
        });
        Assert.Empty(index.LookupExact("replaced.example"));
        Assert.Equal(count, index.IndicatorCount);
    }
}
