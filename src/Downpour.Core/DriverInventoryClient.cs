using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class DriverInventoryClient(string pipeName = DriverInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.DriverInventory.v1";
    private const int MaximumRows = 512;
    private readonly string _pipeName = pipeName;

    public async Task<DriverInventorySnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);

            var snapshot = await BoundedJson.DeserializeAsync<DriverInventorySnapshot>(pipe, timeout.Token);
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
