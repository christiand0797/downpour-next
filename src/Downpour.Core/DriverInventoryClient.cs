using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed class DriverInventoryClient(string pipeName = DriverInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.DriverInventory.v1";
    private const int MaximumPayloadBytes = 1_048_576;
    private const int MaximumRows = 512;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _pipeName = pipeName;

    public async Task<DriverInventorySnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
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
            var snapshot = await JsonSerializer.DeserializeAsync<DriverInventorySnapshot>(payload, JsonOptions, timeout.Token);
            if (snapshot is null || snapshot.SchemaVersion != 1 || snapshot.DriverCount < 0 ||
                snapshot.Drivers is null || snapshot.Warnings is null ||
                snapshot.Drivers.Count > MaximumRows || snapshot.Warnings.Count > 64 ||
                snapshot.Drivers.Any(driver => driver is null || driver.Name is null || driver.ImagePath is null || driver.Name.Length > 512 || driver.ImagePath.Length > 512) ||
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
