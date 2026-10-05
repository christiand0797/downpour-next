using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class InstalledSoftwareInventoryClient(string pipeName = InstalledSoftwareInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.InstalledSoftwareInventory.v1";
    private const int MaximumRows = 1000;
    private readonly string _pipeName = pipeName;

    public async Task<InstalledSoftwareSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<InstalledSoftwareSnapshot>(pipe, timeout.Token);
            if (snapshot is null || snapshot.SchemaVersion != 1 || snapshot.CapturedAtUtc == default ||
                snapshot.CollectionStatus is not ("Available" or "Partial") || snapshot.TotalCount < 0 ||
                snapshot.Software is null || snapshot.Warnings is null || snapshot.Software.Count > MaximumRows || snapshot.Warnings.Count > 16 ||
                snapshot.Software.Any(row => row is null || !ValidText(row.Name, 160, required: true) ||
                    !ValidText(row.Version, 160, required: false) || !ValidText(row.Publisher, 160, required: false) ||
                    row.RegistryScope is not ("Machine" or "Current user")) ||
                snapshot.Warnings.Any(warning => warning is null || warning.Length > 256 || warning.Any(char.IsControl)))
                return null;
            return snapshot;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (JsonReaderException) { return null; }
        catch (JsonSerializationException) { return null; }
    }

    private static bool ValidText(string value, int maxLength, bool required) =>
        value is not null && value.Length <= maxLength && (!required || !string.IsNullOrWhiteSpace(value)) && !value.Any(char.IsControl);
}
