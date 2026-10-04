using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class NetworkInventoryClient(string pipeName = NetworkInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.NetworkInventory.v1";
    private const int MaximumInterfaces = 32;
    private const int MaximumConnections = 256;
    private readonly string _pipeName = pipeName;

    public async Task<NetworkInventorySnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);

            var snapshot = await BoundedJson.DeserializeAsync<NetworkInventorySnapshot>(pipe, timeout.Token);
            if (snapshot is null || snapshot.SchemaVersion != 1 || snapshot.TotalConnectionCount < 0 ||
                snapshot.Interfaces is null || snapshot.Connections is null || snapshot.Warnings is null ||
                snapshot.Interfaces.Count > MaximumInterfaces || snapshot.Connections.Count > MaximumConnections || snapshot.Warnings.Count > 64 ||
                snapshot.Interfaces.Any(row => row is null || row.Name is null || row.Description is null || row.Status is null ||
                    row.Name.Length > 256 || row.Description.Length > 256 || row.Status.Length > 64 ||
                    row.ReceiveBytesPerSecond < 0 || row.SendBytesPerSecond < 0 || row.TotalReceivedBytes < 0 || row.TotalSentBytes < 0) ||
                snapshot.Connections.Any(row => row is null || row.LocalEndpoint is null || row.RemoteEndpoint is null || row.State is null ||
                    row.LocalEndpoint.Length > 256 || row.RemoteEndpoint.Length > 256 || row.State.Length > 64) ||
                snapshot.Warnings.Any(warning => warning is null || warning.Length > 512))
            {
                return null;
            }

            return snapshot;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (JsonReaderException)
        {
            return null;
        }
        catch (JsonSerializationException)
        {
            return null;
        }
    }
}
