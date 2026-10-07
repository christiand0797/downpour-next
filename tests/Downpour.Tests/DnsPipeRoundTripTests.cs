using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class DnsPipeRoundTripTests
{
    [Fact]
    public async Task LiveResolverCacheRoundTripsThroughThePipeAndValidates()
    {
        var folder = Path.Combine(Path.GetTempPath(), "downpour_dns_rt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var pipeName = "Downpour.Test.Dns." + Guid.NewGuid().ToString("N");
        var provider = new DnsInventoryProvider(Path.Combine(folder, "baseline.json"));
        using var worker = new DnsInventoryPipeWorker(provider, NullLogger<DnsInventoryPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var snapshot = await new DnsInventoryClient(pipeName).TryGetSnapshotAsync();
            Assert.NotNull(snapshot); // null is what the DNS page shows as "sensor offline"
            // Record types must be real DNS types (the old struct layout produced 19788 for every entry).
            Assert.All(snapshot!.Entries, entry => Assert.InRange(entry.RecordType, 0, 1024));
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
            Directory.Delete(folder, true);
        }
    }
}

/// <summary>
/// End-to-end pipe tests for the length-prefixed inventory endpoints. These failed before the clients read the 4-byte
/// prefix: every live reply was discarded and the USB and Wi-Fi pages showed the sensor as offline.
/// </summary>
public sealed class FramedInventoryPipeRoundTripTests
{
    [Fact]
    public async Task UsbInventoryRoundTripsThroughThePipe()
    {
        var pipeName = "Downpour.Test.Usb." + Guid.NewGuid().ToString("N");
        using var worker = new UsbInventoryPipeWorker(new UsbInventoryProvider(), NullLogger<UsbInventoryPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            Assert.NotNull(await new UsbInventoryClient(pipeName).TryGetSnapshotAsync());
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task WirelessInventoryRoundTripsThroughThePipe()
    {
        var pipeName = "Downpour.Test.Wifi." + Guid.NewGuid().ToString("N");
        using var worker = new WirelessInventoryPipeWorker(new WirelessInventoryProvider(), NullLogger<WirelessInventoryPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            Assert.NotNull(await new WirelessInventoryClient(pipeName).TryGetSnapshotAsync());
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task FramedReaderRejectsBadLengths()
    {
        foreach (var length in new[] { 0, -1, Downpour.Core.BoundedJson.MaximumPayloadBytes + 1 })
        {
            var bytes = BitConverter.GetBytes(length);
            await Assert.ThrowsAsync<InvalidDataException>(() => Downpour.Core.BoundedJson.DeserializeFramedAsync<object>(new MemoryStream(bytes), CancellationToken.None));
        }
        // Truncated payload: claims 10 bytes, provides 2.
        await Assert.ThrowsAsync<EndOfStreamException>(() => Downpour.Core.BoundedJson.DeserializeFramedAsync<object>(
            new MemoryStream([.. BitConverter.GetBytes(10), (byte)'{', (byte)'}']), CancellationToken.None));
    }
}

public sealed class UsbStorageIdentityTests
{
    [Theory]
    [InlineData("")]
    [InlineData("C")]
    [InlineData("CC:")]
    [InlineData("1:")]
    [InlineData("C:' OR 1=1")]
    public void RejectsMalformedDriveLetters(string letter) =>
        Assert.Null(UsbInventoryProvider.ResolveStorageInstanceId(letter));

    [Fact]
    public void SystemDriveIsNeverReportedAsUsbStorage()
    {
        var system = Path.GetPathRoot(Environment.SystemDirectory)!.TrimEnd(Path.DirectorySeparatorChar);
        var id = UsbInventoryProvider.ResolveStorageInstanceId(system);
        Assert.True(id is null || id.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase));
    }
}
