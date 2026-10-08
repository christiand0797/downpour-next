namespace Downpour.Contracts;

/// <summary>One Plug and Play device with its driver, as Device Manager shows it.</summary>
public sealed record DeviceEntry(
    string InstanceId,
    string Name,
    string Class,
    string Manufacturer,
    string Status,
    int ProblemCode,
    bool Present,
    string? DriverProvider,
    string? DriverVersion,
    DateTimeOffset? DriverDate,
    string? InfName,
    bool? DriverSigned,
    string? DriverSigner,
    string? HardwareId);

/// <summary>A driver update Windows Update offers for this PC (found by a read-only search).</summary>
public sealed record DriverUpdateOffer(
    string Title,
    string? DriverClass,
    string? DriverModel,
    string? DriverProvider,
    string? DriverManufacturer,
    string? DriverHardwareId,
    DateTimeOffset? DriverDate,
    long? MaximumDownloadBytes);

public static class DeviceOperations
{
    public const string Snapshot = "snapshot";
    public const string SearchUpdates = "search-updates";
}

public static class UpdateSearchStates
{
    public const string NotSearched = "not-searched";
    public const string Searching = "searching";
    public const string Done = "done";
    public const string Failed = "failed";
}

public sealed record DeviceInventorySnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<DeviceEntry> Devices,
    IReadOnlyList<DriverUpdateOffer> Updates,
    string UpdateSearchState,
    DateTimeOffset? UpdatesCheckedAtUtc,
    string? UpdateSearchError,
    IReadOnlyList<string> Warnings);

public sealed record DeviceRequest(int SchemaVersion, string Operation);

public sealed record DeviceResponse(int SchemaVersion, bool Accepted, string ResultCode, DeviceInventorySnapshot? Snapshot);
