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
        Assert.All(first.Warnings, warning =>
        {
            if (!warning.Contains("TCP listener(s) appear", StringComparison.Ordinal)) return;
            Assert.Contains("not proof of tampering", warning);
        });
    }

    [Fact]
    public void ListenerView_AgreesOnIdenticalSets()
    {
        Assert.Null(NetworkInventoryProvider.DescribeListenerViewDisagreement(
            ["0.0.0.0:135", "[::]:443"], ["[::]:443", "0.0.0.0:135"]));
    }

    [Fact]
    public void ListenerView_IsCaseInsensitive()
    {
        Assert.Null(NetworkInventoryProvider.DescribeListenerViewDisagreement(
            ["fe80::1%12:445"], ["FE80::1%12:445"]));
    }

    [Fact]
    public void ListenerView_NamesOneSidedEndpointsAsAnAnomalyNotTampering()
    {
        var warning = NetworkInventoryProvider.DescribeListenerViewDisagreement(
            ["0.0.0.0:135", "0.0.0.0:445"], ["0.0.0.0:135"]);
        Assert.NotNull(warning);
        Assert.Contains("0.0.0.0:445", warning);
        Assert.Contains("1 TCP listener(s)", warning);
        Assert.Contains("read a moment apart", warning);
        Assert.Contains("not proof of tampering", warning);
    }

    [Fact]
    public void ListenerView_StaysSilentWhenEitherTableIsEmpty()
    {
        Assert.Null(NetworkInventoryProvider.DescribeListenerViewDisagreement(["0.0.0.0:135"], []));
        Assert.Null(NetworkInventoryProvider.DescribeListenerViewDisagreement([], ["0.0.0.0:135"]));
    }

    [Fact]
    public void ListenerView_StaysSilentAboveTenDifferences()
    {
        var eleven = Enumerable.Range(1, 11).Select(port => $"0.0.0.0:{port}").ToArray();
        Assert.Null(NetworkInventoryProvider.DescribeListenerViewDisagreement(eleven, ["0.0.0.0:9000"]));

        var ten = Enumerable.Range(1, 10).Select(port => $"0.0.0.0:{port}").ToArray();
        Assert.NotNull(NetworkInventoryProvider.DescribeListenerViewDisagreement(ten, ["0.0.0.0:1"]));
    }
}
