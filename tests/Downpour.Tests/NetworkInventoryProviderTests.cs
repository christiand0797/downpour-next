using Downpour.Service;

namespace Downpour.Tests;

public sealed class NetworkInventoryProviderTests
{
    [Fact]
    public void CaptureReturnsBoundedReadOnlyNetworkInventory()
    {
        var provider = new NetworkInventoryProvider();

        var first = provider.Capture();
        var second = provider.Capture();

        Assert.Equal(1, first.SchemaVersion);
        Assert.Equal(1, second.SchemaVersion);
        Assert.InRange(first.Interfaces.Count, 0, 32);
        Assert.InRange(first.Connections.Count, 0, 256);
        Assert.True(first.TotalConnectionCount >= first.Connections.Count);
        Assert.All(first.Interfaces, row =>
        {
            Assert.InRange(row.Name.Length, 0, 256);
            Assert.InRange(row.Description.Length, 0, 256);
            Assert.True(row.TotalReceivedBytes >= 0);
            Assert.True(row.TotalSentBytes >= 0);
            Assert.True(row.ReceiveBytesPerSecond is null or >= 0);
            Assert.True(row.SendBytesPerSecond is null or >= 0);
        });
        Assert.All(first.Connections, row =>
        {
            Assert.InRange(row.LocalEndpoint.Length, 1, 256);
            Assert.InRange(row.RemoteEndpoint.Length, 1, 256);
            Assert.InRange(row.State.Length, 1, 64);
        });
        Assert.NotNull(second.Warnings);
    }
}
