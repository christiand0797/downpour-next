using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class UsbInventoryClient(string pipeName = UsbInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.UsbInventory.v1";
    private const int MaximumConnected = 64;
    private const int MaximumHistory = 1024;
    private const int MaximumFindings = 256;
    private const int MaximumText = 512;
    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal) { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

    public async Task<UsbSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<UsbSnapshot>(pipe, timeout.Token);
            return IsValid(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
            or JsonReaderException or JsonSerializationException)
        {
            return null;
        }
    }

    public static bool IsValid(UsbSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.ConnectedDevices is { Count: <= MaximumConnected }
        && snapshot.History is { Count: <= MaximumHistory }
        && snapshot.Findings is { Count: <= MaximumFindings }
        && snapshot.Warnings is { Count: <= 64 }
        && snapshot.ConnectedDevices.All(d => d is not null && Text(d.DriveLetter) && Text(d.VolumeLabel) && Text(d.FileSystem) && Text(d.Vendor) && Text(d.Product) && Text(d.SerialNumber) && Text(d.DriveType))
        && snapshot.History.All(h => h is not null && Text(h.DeviceId) && Text(h.Vendor) && Text(h.Product) && Text(h.Revision) && Text(h.SerialNumber) && Text(h.FriendlyName) && Text(h.HardwareId))
        && snapshot.Findings.All(f => f is not null && Severities.Contains(f.Severity) && Text(f.Technique) && Text(f.Summary) && Text(f.Indicator))
        && snapshot.Warnings.All(Text);

    private static bool Text(string? value) => value is not null && value.Length <= MaximumText * 2;
}
