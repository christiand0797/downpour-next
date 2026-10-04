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
        Assert.InRange(snapshot.TopProcesses.Count, 1, SystemSnapshotProvider.MaximumProcessRows);
        Assert.Equal(snapshot.TopProcesses.OrderByDescending(process => process.WorkingSetBytes).Select(process => process.ProcessId),
            snapshot.TopProcesses.Select(process => process.ProcessId));
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

    [Fact]
    public void ClientSnapshotValidationRejectsWrongSchemaAndOutOfRangeCounters()
    {
        var valid = new Downpour.Contracts.SystemHealthSnapshot(1, DateTimeOffset.UtcNow, 1, 50, 1024, 512, 2,
            [new Downpour.Contracts.ProcessSnapshot(10, "safe", 128, 1)], []);
        var wrongSchema = valid with { SchemaVersion = 2 };
        var impossibleCpu = valid with { CpuPercent = 140 };
        var badMemory = valid with { MemoryAvailableBytes = 2048 };

        Assert.True(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(wrongSchema));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(impossibleCpu));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(badMemory));
    }

    [Fact]
    public void ClientSnapshotValidationBoundsProcessInventoryAndNames()
    {
        var row = new Downpour.Contracts.ProcessSnapshot(10, "safe", 128, 1);
        var rows = Enumerable.Range(0, 512).Select(index => row with { ProcessId = index + 1 }).ToArray();
        var snapshot = new Downpour.Contracts.SystemHealthSnapshot(1, DateTimeOffset.UtcNow, 513, 50, 1024, 512, 2, rows, []);

        Assert.True(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(snapshot));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(snapshot with { TopProcesses = [.. rows, row with { ProcessId = 513 }] }));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(snapshot with { TopProcesses = [row with { Name = new string('x', 129) }] }));
    }
}
