using Downpour.Service;
using System.Diagnostics;

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
        if (snapshot.MemoryCommitLimitBytes is { } commitLimit && snapshot.MemoryCommittedBytes is { } committed)
            Assert.InRange<ulong>(committed, 0, commitLimit);
        else
            Assert.Contains(snapshot.Warnings, warning => warning.Contains("commit counters", StringComparison.OrdinalIgnoreCase));
        Assert.True(snapshot.DiskReadBytesPerSecond is null or >= 0);
        Assert.True(snapshot.DiskWriteBytesPerSecond is null or >= 0);
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
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid with { DiskReadBytesPerSecond = -1 }));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid with { DiskWriteBytesPerSecond = -1 }));
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

    [Fact]
    public void ProcessCpuPercentUsesTotalMachineCapacityAndRejectsInvalidDeltas()
    {
        var oneCoreSecond = TimeSpan.TicksPerSecond;

        Assert.Equal(25, SystemSnapshotProvider.CalculateProcessCpuPercent(0, oneCoreSecond, TimeSpan.FromSeconds(1), 4));
        Assert.Equal(100, SystemSnapshotProvider.CalculateProcessCpuPercent(0, oneCoreSecond * 4, TimeSpan.FromSeconds(1), 4));
        Assert.Null(SystemSnapshotProvider.CalculateProcessCpuPercent(10, 9, TimeSpan.FromSeconds(1), 4));
        Assert.Null(SystemSnapshotProvider.CalculateProcessCpuPercent(0, 10, TimeSpan.Zero, 4));
        Assert.Null(SystemSnapshotProvider.CalculateProcessCpuPercent(0, 10, TimeSpan.FromSeconds(1), 0));
    }

    [Fact]
    public void CaptureReportsProcessCpuAfterASecondAccessibleSample()
    {
        var provider = new SystemSnapshotProvider();
        _ = provider.Capture();
        var start = Stopwatch.GetTimestamp();
        while (Stopwatch.GetElapsedTime(start) < TimeSpan.FromMilliseconds(180))
            _ = Math.Sqrt(Stopwatch.GetTimestamp());

        var current = provider.Capture().TopProcesses.Single(process => process.ProcessId == Environment.ProcessId);

        Assert.NotNull(current.CpuPercent);
        Assert.InRange(current.CpuPercent.Value, 0, 100);
    }

    [Fact]
    public void PhysicalDiskCountersRemainUnknownOrReturnNonnegativeRates()
    {
        using var provider = new SystemSnapshotProvider();
        _ = provider.Capture();
        Thread.Sleep(TimeSpan.FromMilliseconds(1100));

        var snapshot = provider.Capture();

        Assert.True(snapshot.DiskReadBytesPerSecond is null or >= 0);
        Assert.True(snapshot.DiskWriteBytesPerSecond is null or >= 0);
    }

    [Fact]
    public void ClientSnapshotValidationRejectsOutOfRangePerProcessCpu()
    {
        var valid = new Downpour.Contracts.SystemHealthSnapshot(1, DateTimeOffset.UtcNow, 1, 50, 1024, 512, 2,
            [new Downpour.Contracts.ProcessSnapshot(10, "safe", 128, 1, 8.5)], []);

        Assert.True(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid with
        {
            TopProcesses = [valid.TopProcesses[0] with { CpuPercent = 100.1 }]
        }));
    }

    [Fact]
    public void CommitCounterValidationRequiresAConsistentSystemWidePair()
    {
        var valid = new Downpour.Contracts.SystemHealthSnapshot(1, DateTimeOffset.UtcNow, 1, 50, 1024, 512, 2,
            [new Downpour.Contracts.ProcessSnapshot(10, "safe", 128, 1)], [], 4096, 2048);

        Assert.True(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid with { MemoryCommittedBytes = 8192 }));
        Assert.False(Downpour.Core.SystemSnapshotClient.IsValidSnapshot(valid with { MemoryCommitLimitBytes = null }));
    }

    [Fact]
    public void PerformancePageCountsConvertSaturatingPagesToBytes()
    {
        Assert.Equal(16_384UL, SystemSnapshotProvider.PagesToBytes((nuint)4, (nuint)4_096));
        Assert.Equal(0UL, SystemSnapshotProvider.PagesToBytes((nuint)4, 0));
        Assert.Equal(ulong.MaxValue, SystemSnapshotProvider.PagesToBytes(nuint.MaxValue, (nuint)4_096));
    }
}
