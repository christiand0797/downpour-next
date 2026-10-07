namespace Downpour.Contracts;

public sealed record UsbConnectedDevice(
    string DriveLetter,
    string VolumeLabel,
    string FileSystem,
    long TotalSizeBytes,
    long FreeSizeBytes,
    string Vendor,
    string Product,
    string SerialNumber,
    bool HasAutorun,
    bool HasSuspiciousFiles,
    string DriveType,
    string? PnpDeviceId = null);

public sealed record UsbDeviceHistoryEntry(
    string DeviceId,
    string Vendor,
    string Product,
    string Revision,
    string SerialNumber,
    string FriendlyName,
    string HardwareId);

public sealed record UsbFinding(
    string Severity,
    string Technique,
    string Summary,
    string Indicator);

public sealed record UsbSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    bool UsbStorageServiceEnabled,
    IReadOnlyList<UsbConnectedDevice> ConnectedDevices,
    IReadOnlyList<UsbDeviceHistoryEntry> History,
    IReadOnlyList<UsbFinding> Findings,
    IReadOnlyList<string> Warnings);
