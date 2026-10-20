using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatFeedBrowserTests
{
    private static ParsedThreatFeed Feed(int count) => new(Enumerable.Range(0, count)
        .Select(i => new ThreatIndicator(IndicatorType.Domain, $"node{i:D6}.example", i % 2 == 0 ? "even" : "odd")).ToArray(), 0, []);

    [Fact]
    public void PagesCoverTheEntireFeedWithoutDroppingOrRepeatingRows()
    {
        var feed = Feed(1203);
        var first = ThreatFeedBrowser.Read(feed, null);
        var second = ThreatFeedBrowser.Read(feed, null, first.NextOffset!.Value);
        var last = ThreatFeedBrowser.Read(feed, null, second.NextOffset!.Value);
        Assert.Equal(1203, first.Total);
        Assert.Equal(500, first.Rows.Count);
        Assert.Equal(500, second.Rows.Count);
        Assert.Equal(203, last.Rows.Count);
        Assert.Null(last.NextOffset);
        Assert.Equal(feed.Indicators.Select(i => i.Value), first.Rows.Concat(second.Rows).Concat(last.Rows).Select(r => r.Value));
    }

    [Fact]
    public void SearchIncludesEveryRowAndPaginationUsesMatchingOffsets()
    {
        var feed = Feed(2403);
        var first = ThreatFeedBrowser.Read(feed, " EVEN ");
        var second = ThreatFeedBrowser.Read(feed, "even", first.NextOffset!.Value);
        var last = ThreatFeedBrowser.Read(feed, "even", second.NextOffset!.Value);
        Assert.Equal(1202, first.Total);
        Assert.Equal(feed.Indicators.Where(i => i.Label == "even").Select(i => i.Value),
            first.Rows.Concat(second.Rows).Concat(last.Rows).Select(r => r.Value));
        Assert.Equal("node002402.example", Assert.Single(ThreatFeedBrowser.Read(feed, "002402").Rows).Value);
    }

    [Theory]
    [InlineData(1234, 1000, 234)]
    [InlineData(1000, 500, 500)]
    [InlineData(0, 0, 0)]
    public void OffsetAfterARefreshClampsToTheLastExistingPage(int count, int expectedOffset, int expectedRows)
    {
        var result = ThreatFeedBrowser.Read(Feed(count), null, 3000);
        Assert.Equal(expectedOffset, result.Offset);
        Assert.Equal(expectedRows, result.Rows.Count);
        Assert.Null(result.NextOffset);
    }

    [Fact]
    public void ToolRowsFollowIndicatorsAndRemainSearchableByTechnique()
    {
        var feed = Feed(500) with { Lolbins = [new("certutil.exe", "Download", "T1105")] };
        var page = ThreatFeedBrowser.Read(feed, null, 500);
        Assert.Equal(501, page.Total);
        Assert.Equal("built-in tool", Assert.Single(page.Rows).Type);
        Assert.Equal("certutil.exe", Assert.Single(ThreatFeedBrowser.Read(feed, "t1105").Rows).Value);
    }

    [Fact]
    public void ResponseAllocationDoesNotGrowWithEveryScannedIndicator()
    {
        var feed = Feed(100_000);
        _ = ThreatFeedBrowser.Read(Feed(1), null); // JIT before the allocation observation.
        var before = GC.GetAllocatedBytesForCurrentThread();
        var page = ThreatFeedBrowser.Read(feed, null);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(100_000, page.Total);
        Assert.Equal(500, page.Rows.Count);
        Assert.True(allocated < 256 * 1024, $"Browse allocated {allocated} bytes for a single page.");
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(3_000_001)]
    public void InvalidOffsetIsRejected(int offset) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => ThreatFeedBrowser.Read(Feed(1), null, offset));

    [Fact]
    public void InvalidQueriesAndCancellationAreHonored()
    {
        Assert.Throws<ArgumentException>(() => ThreatFeedBrowser.Read(Feed(1), new string('a', 129)));
        Assert.Throws<ArgumentException>(() => ThreatFeedBrowser.Read(Feed(1), "name\n"));
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        Assert.Throws<OperationCanceledException>(() => ThreatFeedBrowser.Read(Feed(1), null, cancellationToken: cancel.Token));
    }
}
