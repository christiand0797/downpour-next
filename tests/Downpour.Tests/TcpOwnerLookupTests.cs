using System.Net;
using System.Net.Sockets;
using Downpour.Service;
using Xunit;

namespace Downpour.Tests;

public sealed class TcpOwnerLookupTests
{
    [Fact]
    public void ListenerTableMapsALoopbackPortToThisProcess()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var owners = TcpOwnerLookup.CaptureListenerOwners();

            Assert.True(owners.TryGetValue($"127.0.0.1:{port}", out var processId), $"the test listener was not in the owner table ({owners.Count} rows: {string.Join(", ", owners.Take(10).Select(row => $"{row.Key}={row.Value}"))})");
            Assert.Equal(Environment.ProcessId, processId);

            var names = new Dictionary<int, string?>();
            Assert.Equal(Path.GetFileName(Environment.ProcessPath), TcpOwnerLookup.ProcessName(processId, names));
            Assert.Equal(TcpOwnerLookup.ProcessName(processId, names), TcpOwnerLookup.ProcessName(processId, new Dictionary<int, string?>()));
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void UnknownProcessIdsResolveToNull()
    {
        var names = new Dictionary<int, string?>();
        Assert.Null(TcpOwnerLookup.ProcessName(0, names));
        Assert.Null(TcpOwnerLookup.ProcessName(-1, names));
    }
}
