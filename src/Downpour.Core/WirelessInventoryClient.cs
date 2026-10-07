using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class WirelessInventoryClient(string pipeName = WirelessInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.WirelessInventory.v1";
    private const int MaximumNetworks = 256;
    private const int MaximumBluetoothDevices = 256;
    private const int MaximumFindings = 256;
    private const int MaximumText = 512;
    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal) { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

    public async Task<WirelessSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeFramedAsync<WirelessSnapshot>(pipe, timeout.Token);
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

    public static bool IsValid(WirelessSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.WifiNetworks is { Count: <= MaximumNetworks }
        && snapshot.BluetoothDevices is { Count: <= MaximumBluetoothDevices }
        && snapshot.Findings is { Count: <= MaximumFindings }
        && snapshot.Warnings is { Count: <= 64 }
        && (snapshot.ConnectedSsid is null || Text(snapshot.ConnectedSsid))
        && (snapshot.ConnectedBssid is null || Text(snapshot.ConnectedBssid))
        && snapshot.WifiNetworks.All(n => n is not null && Text(n.Ssid) && Text(n.Bssid) && Text(n.Authentication) && Text(n.Cipher) && Text(n.NetworkType))
        && snapshot.BluetoothDevices.All(b => b is not null && Text(b.Address) && Text(b.Name) && Text(b.RegistryPath))
        && snapshot.Findings.All(f => f is not null && Severities.Contains(f.Severity) && Text(f.Technique) && Text(f.Summary) && Text(f.Indicator))
        && snapshot.Warnings.All(Text);

    private static bool Text(string? value) => value is not null && value.Length <= MaximumText * 2;
}
