using System.Text;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatFeedFreshnessTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);
    private static ThreatFeedDefinition Feed(string id) => ThreatFeedCatalog.Find(id)!;
    private static ParsedThreatFeed Parse(string id, string text) => ThreatFeedParser.Parse(Feed(id), Encoding.UTF8.GetBytes(text));

    [Theory]
    [InlineData("blp-phishing", "# Last modified: 2026-10-18 12:00:00 UTC\nlisted.example")]
    [InlineData("hagezi-tif", "# Last modified: 18 Oct 2026 12:00 UTC\nlisted.example")]
    [InlineData("urlhaus", "# Last updated: 2026-10-18 12:00:00 (UTC) #\n0.0.0.0 listed.example")]
    [InlineData("feodo", "# Last updated: 2026-10-18 12:00:00 UTC #\n2026-10-17,8.8.4.4,443,online,2026-10-18,Botnet")]
    public void ProviderPublicationHeadersAreReadWithoutUsingDownloadTime(string id, string payload)
    {
        var parsed = Parse(id, payload);
        Assert.Equal(Now.AddDays(-1), parsed.SourcePublishedAtUtc);
        Assert.Null(parsed.PublicationError);
        var status = ThreatFeedFreshness.Evaluate(Feed(id), parsed, Now, Now);
        Assert.Equal(ThreatSourceFreshness.Fresh, status.State);
        Assert.True(status.MatchingEnabled);
    }

    [Theory]
    [InlineData("# Last modified: nonsense\nlisted.example")]
    [InlineData("# Last modified: 2026-10-18 12:00:00 UTC\n# Last modified: 2026-10-18 12:00:00 UTC\nlisted.example")]
    [InlineData("listed.example")]
    [InlineData("# Last modified: 9999-12-31 23:59:59 UTC\nlisted.example")]
    public void MissingInvalidDuplicateAndFutureExpectedMetadataCannotBypassExpiry(string payload)
    {
        var status = ThreatFeedFreshness.Evaluate(Feed("blp-phishing"), Parse("blp-phishing", payload), Now, Now);
        Assert.Equal(ThreatSourceFreshness.Unknown, status.State);
        Assert.False(status.MatchingEnabled);
        Assert.Null(status.PublishedAtUtc);
    }

    [Fact]
    public void NewlyDownloadedOldPublicationRemainsExpiredAndCanStillBeBrowsed()
    {
        var parsed = Parse("blp-phishing", "# Last modified: 2026-07-06 00:40:29 UTC\nlisted.example");
        var status = ThreatFeedFreshness.Evaluate(Feed("blp-phishing"), parsed, Now, Now);
        Assert.Equal(ThreatSourceFreshness.Expired, status.State);
        Assert.False(status.MatchingEnabled);
        Assert.Equal(1, ThreatFeedBrowser.Read(parsed, null).Total);
    }

    [Fact]
    public void ExpiryBoundaryIsDeterministicAndDoesNotRenewOnRedownload()
    {
        var parsed = Parse("blp-phishing", "# Last modified: 2026-10-18 12:00:00 UTC\nlisted.example");
        var expiry = parsed.SourcePublishedAtUtc!.Value + Feed("blp-phishing").MaximumSourceAge!.Value;
        Assert.True(ThreatFeedFreshness.Evaluate(Feed("blp-phishing"), parsed, expiry, expiry.AddTicks(-1)).MatchingEnabled);
        Assert.False(ThreatFeedFreshness.Evaluate(Feed("blp-phishing"), parsed, expiry, expiry).MatchingEnabled);
    }

    [Fact]
    public void UnknownSourceDateIsNotSynthesizedFromDownloadOrIocText()
    {
        var parsed = Parse("stalkerware", "# Last modified: 2026-10-18 12:00:00 UTC\nlisted.example");
        var status = ThreatFeedFreshness.Evaluate(Feed("stalkerware"), parsed, Now, Now);
        Assert.Null(status.PublishedAtUtc);
        Assert.Equal(ThreatSourceFreshness.Unknown, status.State);
        Assert.True(status.MatchingEnabled);
        Assert.False(ThreatFeedFreshness.Evaluate(Feed("stalkerware"), parsed, Now.AddDays(-31), Now).MatchingEnabled);
    }

    [Fact]
    public void HistoricalNetworkListsAreContextOnlyButHistoricalFileHashesRemainUseful()
    {
        var network = Parse("amnesty-pegasus", "listed.example");
        var networkStatus = ThreatFeedFreshness.Evaluate(Feed("amnesty-pegasus"), network, Now, Now);
        Assert.Equal(ThreatSourceFreshness.Historical, networkStatus.State);
        Assert.False(networkStatus.MatchingEnabled);
        var hashes = Parse("digitalside-hash", "{\"generatedAt\":\"2024-10-18 09:08:21\",\"lookup\":{\"1\":{\"sha256\":\"" + new string('a', 64) + "\"}}}");
        var hashStatus = ThreatFeedFreshness.Evaluate(Feed("digitalside-hash"), hashes, Now, Now);
        Assert.Equal(new DateTimeOffset(2024, 10, 18, 9, 8, 21, TimeSpan.Zero), hashStatus.PublishedAtUtc);
        Assert.Equal(ThreatSourceFreshness.Historical, hashStatus.State);
        Assert.True(hashStatus.MatchingEnabled);
    }

    [Theory]
    [InlineData("\"today\"")]
    [InlineData("true")]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("9223372036854775807")]
    public void SpamhausMalformedMetadataDoesNotThrowOrEnableMatching(string timestamp)
    {
        var parsed = Parse("spamhaus-drop", "{\"cidr\":\"8.8.4.0/24\"}\n{\"type\":\"metadata\",\"timestamp\":" + timestamp + "}");
        Assert.NotNull(parsed.PublicationError);
        Assert.False(ThreatFeedFreshness.Evaluate(Feed("spamhaus-drop"), parsed, Now, Now).MatchingEnabled);
    }

    [Fact]
    public void SpamhausUnixTimestampAndDuplicateMetadataAreHandled()
    {
        var metadata = "{\"type\":\"metadata\",\"timestamp\":" + Now.AddDays(-1).ToUnixTimeSeconds() + "}";
        var parsed = Parse("spamhaus-drop", "{\"cidr\":\"8.8.4.0/24\"}\n" + metadata);
        Assert.Equal(Now.AddDays(-1), parsed.SourcePublishedAtUtc);
        Assert.True(ThreatFeedFreshness.Evaluate(Feed("spamhaus-drop"), parsed, Now, Now).MatchingEnabled);
        var duplicate = Parse("spamhaus-drop", "{\"cidr\":\"8.8.4.0/24\"}\n" + metadata + "\n" + metadata);
        Assert.False(ThreatFeedFreshness.Evaluate(Feed("spamhaus-drop"), duplicate, Now, Now).MatchingEnabled);
        Assert.False(ThreatFeedFreshness.Evaluate(Feed("spamhaus-drop"), Parse("spamhaus-drop", "{\"cidr\":\"8.8.4.0/24\"}"), Now, Now).MatchingEnabled);
    }
}
