using System.Diagnostics;
using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class PerformanceAndContractTests
{
    [Fact]
    public void CompactIndexBuildsTwoHundredThousandDomainsWithinBudget()
    {
        var feed = ThreatFeedCatalog.Find("tweetfeed-domains")! with { IndicatorLimit = 300_000 };
        var indicators = Enumerable.Range(0, 200_000)
            .Select(index => new ThreatIndicator(IndicatorType.Domain, $"host{index}.example.com", "performance"))
            .ToArray();
        var parsed = new ParsedThreatFeed(indicators, 0, []);

        var stopwatch = Stopwatch.StartNew();
        var index = ThreatIndex.Build([(feed, parsed)]);
        stopwatch.Stop();

        Assert.Equal(200_000, index.IndicatorCount);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(30),
            $"Indexing 200,000 domains took {stopwatch.Elapsed.TotalSeconds:F1}s.");
    }

    [Fact]
    public void DatabaseSnapshotRejectsAnUnknownSchemaEvenWhenOtherwiseValid()
    {
        var feed = new ThreatFeedStatus("feed", "Feed", "Provider", ThreatFeedKinds.Domain, "Purpose", "MIT",
            "https://example.test", ThreatFeedStates.Current, 1, DateTimeOffset.UnixEpoch, null, 10, null);
        var snapshot = new ThreatDatabaseSnapshot(1, DateTimeOffset.UnixEpoch, true, 1,
            [feed], [], [], new ThreatDatabaseCoverage(0, 0, 0, 0, null, null), [], []);

        Assert.True(ThreatDatabaseClient.IsValid(snapshot));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { SchemaVersion = 2 }));
        Assert.False(ThreatDatabaseClient.IsValid(snapshot with { TotalIndicators = -1 }));
    }
}
