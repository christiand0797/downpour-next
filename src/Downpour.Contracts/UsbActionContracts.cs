namespace Downpour.Contracts;

public static class UsbActionOperations
{
    public const string PreviewBlockDevice = "preview-block-device";
    public const string BlockDevice = "block-device";
    public const string PreviewUnblockDevice = "preview-unblock-device";
    public const string UnblockDevice = "unblock-device";
    public const string PreviewSetUsbStorage = "preview-set-usbstorage";
    public const string SetUsbStorage = "set-usbstorage";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        PreviewBlockDevice, BlockDevice,
        PreviewUnblockDevice, UnblockDevice,
        PreviewSetUsbStorage, SetUsbStorage
    };
}

/// <summary>
/// Versioned request contract for USB device management actions (DN-008 Phase 4).
/// </summary>
public sealed record UsbActionRequest(
    int SchemaVersion,
    Guid RequestId,
    string Operation,
    string? DeviceId = null,
    string? FriendlyName = null,
    bool UsbStorageEnabled = true,
    string? Reason = null,
    string? ConsentToken = null);

/// <summary>
/// Pre-execution preview of a USB action for operator review and itemized consent.
/// </summary>
public sealed record UsbActionPreview(
    string Operation,
    string? DeviceId,
    string? FriendlyName,
    bool UsbStorageEnabled,
    string? DenyReason,
    string? ConsentToken,
    DateTimeOffset? ExpiresAtUtc,
    IReadOnlyList<string> ExpectedEffects,
    IReadOnlyList<string> Risks);

/// <summary>
/// Response payload for a USB device action request.
/// </summary>
public sealed record UsbActionResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string Message,
    bool ActionsEnabled,
    string? DeviceId = null,
    bool? UsbStorageEnabled = null,
    UsbActionPreview? Preview = null);
