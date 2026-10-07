using Downpour.Core;

namespace Downpour.Tests;

public sealed class CleanupInspectorTests
{
    [Fact]
    public async Task ScanAsyncReturnsPopulatedReportWithExpectedCategories()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var report = await CleanupInspector.ScanAsync(cts.Token);

        Assert.NotNull(report);
        Assert.Equal(1, report.SchemaVersion);
        Assert.True(report.ScannedAtUtc <= DateTimeOffset.UtcNow);
        Assert.True(report.Categories.Count >= 6);

        var keys = report.Categories.Select(c => c.Key).ToHashSet();
        Assert.Contains("user_temp", keys);
        Assert.Contains("win_temp", keys);
        Assert.Contains("thumbnails", keys);
        Assert.Contains("win_error_reports", keys);
        Assert.Contains("recycle_bin", keys);

        Assert.True(report.TotalReclaimableBytes >= 0);
        Assert.True(report.TotalReclaimableFiles >= 0);

        Assert.All(report.Categories, cat =>
        {
            Assert.False(string.IsNullOrWhiteSpace(cat.Label));
            Assert.False(string.IsNullOrWhiteSpace(cat.Description));
            Assert.True(cat.TotalBytes >= 0);
            Assert.True(cat.FileCount >= 0);
            Assert.True(cat.RiskLevel is "Safe" or "Moderate" or "Warning");
        });
    }

    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(512, "512 B")]
    [InlineData(1024, "1.0 KB")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(1048576, "1.0 MB")]
    [InlineData(1073741824, "1.00 GB")]
    [InlineData(5368709120, "5.00 GB")]
    public void FormatBytesFormatsUnitsCorrectly(long bytes, string expected)
    {
        Assert.Equal(expected, CleanupInspector.FormatBytes(bytes));
    }

    [Fact]
    public async Task GenerateTextReportProducesFormattedAuditSummary()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var report = await CleanupInspector.ScanAsync(cts.Token);

        var reportText = CleanupInspector.GenerateTextReport(report);

        Assert.Contains("Downpour Disk & System Cleanup Preview Report", reportText);
        Assert.Contains("Total Potential Reclaimable Space", reportText);
        Assert.Contains("Strictly Read-Only (Preview Mode)", reportText);
        Assert.Contains("User Temporary Files", reportText);
        Assert.Contains("Recycle Bin", reportText);
    }
}
