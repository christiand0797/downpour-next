using Downpour.Service;

namespace Downpour.Tests;

public sealed class SystemSnapshotProviderTests
{
    [Fact]
    public void CaptureReturnsRecentReadOnlySystemInventory()
    {
        var snapshot = new SystemSnapshotProvider().Capture();

        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.InRange((DateTimeOffset.UtcNow - snapshot.CapturedAtUtc).Duration(), TimeSpan.Zero, TimeSpan.FromMinutes(1));
        Assert.True(snapshot.ProcessCount > 0);
        Assert.True(snapshot.TopProcesses.Count <= 8);
        Assert.All(snapshot.TopProcesses, process =>
        {
            Assert.True(process.ProcessId > 0);
            Assert.False(string.IsNullOrWhiteSpace(process.Name));
            Assert.True(process.WorkingSetBytes >= 0);
            Assert.True(process.ThreadCount >= 0);
        });
        Assert.True(snapshot.MemoryTotalBytes > 0);
        Assert.InRange(snapshot.CpuPercent ?? 0, 0, 100);
    }
}
