using Microsoft.Extensions.Logging.Abstractions;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class InstalledSoftwareInventoryTests
{
    [Fact]
    public void ProviderReturnsBoundedDisplayMetadataWithoutExecutableCommands()
    {
        var snapshot = new InstalledSoftwareInventoryProvider().Capture();

        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.True(snapshot.CapturedAtUtc <= DateTimeOffset.UtcNow);
        Assert.Contains(snapshot.CollectionStatus, new[] { "Available", "Partial" });
        Assert.True(snapshot.TotalCount >= snapshot.Software.Count);
        Assert.InRange(snapshot.Software.Count, 0, 1000);
        Assert.InRange(snapshot.Warnings.Count, 0, 16);
        Assert.All(snapshot.Software, entry =>
        {
            Assert.InRange(entry.Name.Length, 1, 160);
            Assert.InRange(entry.Version.Length, 0, 160);
            Assert.InRange(entry.Publisher.Length, 0, 160);
            Assert.Contains(entry.RegistryScope, new[] { "Machine", "Current user" });
        });
    }

    [Fact]
    public async Task ClientReadsBoundedSchemaFromCurrentUserOnlyPipe()
    {
        var pipeName = "Downpour.Software.Test." + Guid.NewGuid().ToString("N");
        var worker = new InstalledSoftwareInventoryPipeWorker(new InstalledSoftwareInventoryProvider(),
            NullLogger<InstalledSoftwareInventoryPipeWorker>.Instance, pipeName);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await worker.StartAsync(timeout.Token);
        try
        {
            var client = new InstalledSoftwareInventoryClient(pipeName);
            var snapshot = await client.TryGetSnapshotAsync(timeout.Token);
            Assert.NotNull(snapshot);
            Assert.Equal(1, snapshot.SchemaVersion);
            Assert.InRange(snapshot.Software.Count, 0, 1000);
            Assert.True(snapshot.TotalCount >= snapshot.Software.Count);
        }
        finally
        {
            await worker.StopAsync(timeout.Token);
        }
    }
}
