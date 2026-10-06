namespace Downpour.Contracts;

public sealed record WifiNetworkEntry(
    string Ssid,
    string Bssid,
    int SignalPercent,
    string Authentication,
    string Cipher,
    int Channel,
    string NetworkType,
    bool IsConnected);

public sealed record BluetoothDeviceEntry(
    string Address,
    string Name,
    string RegistryPath,
    bool IsSuspicious);

public sealed record WirelessFinding(
    string Severity,
    string Technique,
    string Summary,
    string Indicator);

public sealed record WirelessSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    bool WifiAdapterAvailable,
    string? ConnectedSsid,
    string? ConnectedBssid,
    bool BluetoothAdapterEnabled,
    IReadOnlyList<WifiNetworkEntry> WifiNetworks,
    IReadOnlyList<BluetoothDeviceEntry> BluetoothDevices,
    IReadOnlyList<WirelessFinding> Findings,
    IReadOnlyList<string> Warnings);
