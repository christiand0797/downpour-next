using System.Runtime.InteropServices;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class WindowsUpdateSearchBatchTests
{
    [Theory]
    [InlineData(0, 0, "did not complete")]
    [InlineData(1, 0, "did not complete")]
    [InlineData(2, 1, "warnings")]
    [InlineData(2, -1, "invalid")]
    [InlineData(3, 0, "incomplete")]
    [InlineData(4, 0, "failed")]
    [InlineData(5, 0, "aborted")]
    [InlineData(99, 0, "did not complete")]
    public void IncompleteSearchNeverReadsOffersOrBecomesAnEmptySuccess(int code, int warnings, string explanation)
    {
        var batch = new WindowsUpdateSearchBatch<string>();
        Assert.False(batch.AddResult(code, warnings, () => throw new InvalidOperationException("Rejected offers must not be read.")));
        Assert.False(batch.IsComplete);
        Assert.Empty(batch.Updates);
        Assert.Contains(explanation, batch.Failure);
    }

    [Fact]
    public void SuccessfulEmptySearchIsDistinctFromNoSearchOrFailedSearch()
    {
        var batch = new WindowsUpdateSearchBatch<string>();
        Assert.False(batch.IsComplete);
        Assert.True(batch.AddResult(2, 0, () => []));
        Assert.True(batch.IsComplete);
        Assert.Null(batch.Failure);
        Assert.Empty(batch.Updates);
    }

    [Fact]
    public void SuccessfulScopesKeepEveryOfferInSearchOrder()
    {
        var batch = new WindowsUpdateSearchBatch<string>();
        Assert.True(batch.AddResult(2, 0, () => ["software1", "software2"]));
        Assert.True(batch.AddResult(2, 0, () => ["driver1"]));
        Assert.True(batch.IsComplete);
        Assert.Equal(["software1", "software2", "driver1"], batch.Updates);
    }

    [Theory]
    [InlineData(2, 1)]
    [InlineData(3, 0)]
    [InlineData(4, 0)]
    [InlineData(5, 0)]
    public void LaterIncompleteScopeDiscardsEarlierOffersAndCannotBeRevived(int code, int warnings)
    {
        var batch = new WindowsUpdateSearchBatch<string>();
        Assert.True(batch.AddResult(2, 0, () => ["earlier software offer"]));
        Assert.False(batch.AddResult(code, warnings, () => ["partial driver offer"]));
        Assert.False(batch.IsComplete);
        Assert.Empty(batch.Updates);
        var failure = batch.Failure;
        Assert.False(batch.AddResult(2, 0, () => throw new InvalidOperationException("A failed batch stays failed.")));
        Assert.Equal(failure, batch.Failure);
        Assert.Empty(batch.Updates);
    }

    [Fact]
    public void UnreadableCollectionInvalidatesBatchAndPreservesOriginalHResult()
    {
        var batch = new WindowsUpdateSearchBatch<string>();
        batch.AddResult(2, 0, () => ["earlier offer"]);
        var expected = new COMException("Windows Update collection failure", unchecked((int)0x80240022));
        IEnumerable<string> FailingOffers()
        {
            yield return "partially enumerated offer";
            throw expected;
        }

        var actual = Assert.Throws<COMException>(() => batch.AddResult(2, 0, FailingOffers));
        Assert.Same(expected, actual);
        Assert.Equal(unchecked((int)0x80240022), actual.HResult);
        Assert.False(batch.IsComplete);
        Assert.Empty(batch.Updates);
        Assert.Contains("could not be read", batch.Failure);
    }
}
