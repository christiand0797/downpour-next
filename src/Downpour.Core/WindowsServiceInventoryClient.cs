using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class WindowsServiceInventoryClient(string pipeName = WindowsServiceInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.WindowsServiceInventory.v1";
    private const int MaximumServices = 512;
    private const int MaximumWarnings = 64;
    private readonly string _pipeName = pipeName;
    private static readonly HashSet<string> CollectionStatuses = new(StringComparer.Ordinal)
        { "Available", "Partial", "Access denied", "Unavailable" };
    private static readonly HashSet<string> States = new(StringComparer.Ordinal)
        { "Stopped", "Start pending", "Stop pending", "Running", "Continue pending", "Pause pending", "Paused", "Unknown" };
    private static readonly HashSet<string> StartupTypes = new(StringComparer.Ordinal)
        { "Boot", "System", "Automatic", "Manual", "Disabled", "Access denied", "Unknown" };

    public async Task<WindowsServiceInventorySnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);

            var snapshot = await BoundedJson.DeserializeAsync<WindowsServiceInventorySnapshot>(pipe, timeout.Token);
            return IsValidSnapshot(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (InvalidDataException)
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

    internal static bool IsValidSnapshot(WindowsServiceInventorySnapshot? snapshot)
    {
        if (snapshot is null || snapshot.SchemaVersion != 1 || snapshot.ServiceCount < 0 ||
            !CollectionStatuses.Contains(snapshot.CollectionStatus) || snapshot.Services is null || snapshot.Warnings is null ||
            snapshot.ServiceCount < snapshot.Services.Count || snapshot.Services.Count > MaximumServices ||
            snapshot.Warnings.Count > MaximumWarnings)
            return false;

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in snapshot.Services)
        {
            if (service is null || !BoundedText(service.ServiceName, 256, allowEmpty: false) ||
                !BoundedText(service.DisplayName, 256, allowEmpty: false) || !States.Contains(service.State) ||
                !StartupTypes.Contains(service.StartupType) || !names.Add(service.ServiceName))
                return false;
        }

        return snapshot.Warnings.All(warning => BoundedText(warning, 512, allowEmpty: true));
    }

    private static bool BoundedText(string? value, int maximum, bool allowEmpty) =>
        value is not null && value.Length <= maximum && (allowEmpty || !string.IsNullOrWhiteSpace(value)) &&
        !value.Any(char.IsControl);
}
