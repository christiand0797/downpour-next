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
            Assert.InRange(snapshot.TopProcesses.Count, 1, SystemSnapshotProvider.MaximumProcessRows);
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

    [Fact]
    public async Task WindowsServiceInventoryPipeReturnsReadOnlyServiceMetadata()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var pipeName = $"Downpour.ServiceTest.{Guid.NewGuid():N}";
        using var service = new WindowsServiceInventoryPipeWorker(new WindowsServiceInventoryProvider(), NullLogger<WindowsServiceInventoryPipeWorker>.Instance, pipeName);
        var client = new WindowsServiceInventoryClient(pipeName);
        await service.StartAsync(shutdown.Token);

        try
        {
            WindowsServiceInventorySnapshot? snapshot = null;
            for (var attempt = 0; attempt < 10 && snapshot is null; attempt++)
            {
                snapshot = await client.TryGetSnapshotAsync(shutdown.Token);
                if (snapshot is null) await Task.Delay(100, shutdown.Token);
            }

            Assert.NotNull(snapshot);
            Assert.Equal(1, snapshot.SchemaVersion);
            Assert.InRange(snapshot.Services.Count, 0, WindowsServiceInventoryProvider.MaximumServices);
            Assert.Equal(snapshot.Services.Count, snapshot.ServiceCount);
            Assert.Contains(snapshot.Services, row => row.ServiceName.Equals("EventLog", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task NetworkInventoryPipeReturnsBoundedReadOnlySnapshot()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var pipeName = $"Downpour.NetworkTest.{Guid.NewGuid():N}";
        using var service = new NetworkInventoryPipeWorker(new NetworkInventoryProvider(), NullLogger<NetworkInventoryPipeWorker>.Instance, pipeName);
        var client = new NetworkInventoryClient(pipeName);
        await service.StartAsync(shutdown.Token);

        try
        {
            NetworkInventorySnapshot? snapshot = null;
            for (var attempt = 0; attempt < 10 && snapshot is null; attempt++)
            {
                snapshot = await client.TryGetSnapshotAsync(shutdown.Token);
                if (snapshot is null) await Task.Delay(100, shutdown.Token);
            }

            Assert.NotNull(snapshot);
            Assert.Equal(1, snapshot.SchemaVersion);
            Assert.InRange(snapshot.Interfaces.Count, 0, 32);
            Assert.InRange(snapshot.Connections.Count, 0, 256);
            Assert.True(snapshot.TotalConnectionCount >= snapshot.Connections.Count);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }
}
