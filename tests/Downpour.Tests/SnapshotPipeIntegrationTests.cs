using Downpour.Core;
using Downpour.Contracts;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class SnapshotPipeIntegrationTests
{
    [Fact]
    public async Task MissingServiceIsReportedAsUnavailable()
    {
        var client = new SystemSnapshotClient($"Downpour.Missing.{Guid.NewGuid():N}");
        var snapshot = await client.TryGetSnapshotAsync();

        Assert.Null(snapshot);
    }

    [Fact]
    public async Task AuthenticatedLocalClientReadsSchemaVersionedSnapshot()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var pipeName = $"Downpour.Test.{Guid.NewGuid():N}";
        using var service = new SnapshotPipeWorker(new SystemSnapshotProvider(), NullLogger<SnapshotPipeWorker>.Instance, pipeName);
        var client = new SystemSnapshotClient(pipeName);
        await service.StartAsync(shutdown.Token);

        try
        {
            SystemHealthSnapshot? snapshot = null;
            for (var attempt = 0; attempt < 10 && snapshot is null; attempt++)
            {
                snapshot = await client.TryGetSnapshotAsync(shutdown.Token);
                if (snapshot is null) await Task.Delay(100, shutdown.Token);
            }

            Assert.NotNull(snapshot);
            Assert.Equal(1, snapshot.SchemaVersion);
            Assert.True(snapshot.ProcessCount > 0);
            Assert.True(snapshot.TopProcesses.Count <= 8);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task DriverInventoryPipeReturnsBoundedReadOnlySnapshot()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var pipeName = $"Downpour.DriverTest.{Guid.NewGuid():N}";
        using var service = new DriverInventoryPipeWorker(new DriverInventoryProvider(), NullLogger<DriverInventoryPipeWorker>.Instance, pipeName);
        var client = new DriverInventoryClient(pipeName);
        await service.StartAsync(shutdown.Token);

        try
        {
            DriverInventorySnapshot? snapshot = null;
            for (var attempt = 0; attempt < 10 && snapshot is null; attempt++)
            {
                snapshot = await client.TryGetSnapshotAsync(shutdown.Token);
                if (snapshot is null) await Task.Delay(100, shutdown.Token);
            }

            Assert.NotNull(snapshot);
            Assert.Equal(1, snapshot.SchemaVersion);
            Assert.InRange(snapshot.DriverCount, 0, int.MaxValue);
            Assert.InRange(snapshot.Drivers.Count, 0, 512);
            Assert.All(snapshot.Drivers, driver =>
            {
                Assert.InRange(driver.Name.Length, 1, 512);
                Assert.InRange(driver.ImagePath.Length, 0, 512);
            });
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }
}
