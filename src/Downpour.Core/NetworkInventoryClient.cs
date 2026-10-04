using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed class NetworkInventoryClient(string pipeName = NetworkInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.NetworkInventory.v1";
    private const int MaximumPayloadBytes = 1_048_576;
    private const int MaximumInterfaces = 32;
    private const int MaximumConnections = 256;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _pipeName = pipeName;

    public async Task<NetworkInventorySnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);

            await using var payload = new MemoryStream();
            var buffer = new byte[8192];
            int read;
            while ((read = await pipe.ReadAsync(buffer, timeout.Token)) > 0)
            {
                if (payload.Length + read > MaximumPayloadBytes) return null;
                await payload.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
            }

            payload.Position = 0;
            var snapshot = await JsonSerializer.DeserializeAsync<NetworkInventorySnapshot>(payload, JsonOptions, timeout.Token);
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
        catch (JsonException)
        {
            return null;
        }
    }
}
