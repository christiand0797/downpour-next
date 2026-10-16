using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatFeedTypePolicyTests
{
    [Theory]
    [InlineData("phishing-db-domain", "phishing.example", "8.8.8.8", IndicatorType.Domain)]
    [InlineData("threatview-ip", "8.8.8.8", "phishing.example", IndicatorType.Ip)]
    [InlineData("threatview-md5", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "phishing.example", IndicatorType.Md5)]
    [InlineData("threatview-sha", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "8.8.8.8", IndicatorType.Sha1)]
    [InlineData("c2intel-domains", "phishing.example,reported C2", "8.8.8.8,reported C2", IndicatorType.Domain)]
    [InlineData("c2intel-ips", "8.8.8.8,reported C2", "phishing.example,reported C2", IndicatorType.Ip)]
    public void DeclaredFeedKindCannotBeChangedByAValidButDifferentIndicator(string id, string expected, string unexpected, IndicatorType type)
    {
        var feed = ThreatFeedCatalog.Find(id)!;
        var parsed = ThreatFeedParser.Parse(feed, Encoding.UTF8.GetBytes(expected + "\n" + unexpected));

        Assert.Equal(type, Assert.Single(parsed.Indicators).Type);
        Assert.Equal(1, parsed.RejectedLines);
    }

    [Fact]
    public void WrongTypePayloadCannotReplaceTheExistingHashDatabase()
    {
        var feed = ThreatFeedCatalog.Find("threatview-md5")!;
        var content = string.Join('\n', Enumerable.Range(0, 25).Select(n => $"host{n}.example"));

        Assert.Throws<InvalidDataException>(() => ThreatFeedParser.Parse(feed, Encoding.UTF8.GetBytes(content)));
    }

    [Theory]
    [InlineData("http")]
    [InlineData("https")]
    [InlineData("ftp")]
    public void DeferredInvalidIdnHostIsRejectedWithoutEscapingTheParser(string scheme)
    {
        var invalidUrl = scheme + "://\u200d.example/payload";
        var feed = ThreatFeedCatalog.Find("threatview-url")!;
        var parsed = ThreatFeedParser.Parse(feed, Encoding.UTF8.GetBytes("https://valid.example/file\n" + invalidUrl));

        Assert.Equal("valid.example", Assert.Single(parsed.Indicators).Value);
        Assert.Equal(1, parsed.RejectedLines);
        var threatFox = System.Text.Json.JsonSerializer.Serialize(new { group = new[] { new { ioc_type = "url", ioc_value = invalidUrl } } });
        Assert.Throws<InvalidDataException>(() => ThreatFeedParser.Parse(ThreatFeedCatalog.Find("threatfox")!, Encoding.UTF8.GetBytes(threatFox)));
    }
}
