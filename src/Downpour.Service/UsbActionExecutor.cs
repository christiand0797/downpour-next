using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

public sealed record BlockedUsbDeviceRecord(
    string DeviceId,
    string? FriendlyName,
    DateTimeOffset BlockedAtUtc,
    string? Reason);

public interface IUsbDeviceBackend
{
    bool IsDevicePresent(string deviceId);
    bool DisableDevice(string deviceId);
    bool EnableDevice(string deviceId);
    bool IsDeviceDisabled(string deviceId);
    bool GetUsbStorageEnabled();
    void SetUsbStorageEnabled(bool enabled);
}

/// <summary>
/// Production Windows PnP and Registry backend for USB management.
/// </summary>
public sealed class WindowsUsbDeviceBackend : IUsbDeviceBackend
{
    private const int CR_SUCCESS = 0x00000000;
    private const uint CM_LOCATE_DEVNODE_NORMAL = 0x00000000;
    private const uint CM_LOCATE_DEVNODE_PHANTOM = 0x00000001;
    private const uint DN_STARTED = 0x00000008;
    private const uint DN_HAS_PROBLEM = 0x00000400;
    private const uint CM_PROB_DISABLED = 22;

    [DllImport("cfgmgr32.dll", EntryPoint = "CM_Locate_DevNodeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CM_Locate_DevNode(out uint devInst, string devId, uint flags);

    [DllImport("cfgmgr32.dll", SetLastError = true)]
    private static extern int CM_Disable_DevNode(uint devInst, uint flags);

    [DllImport("cfgmgr32.dll", SetLastError = true)]
    private static extern int CM_Enable_DevNode(uint devInst, uint flags);

    [DllImport("cfgmgr32.dll", SetLastError = true)]
    private static extern int CM_Get_DevNode_Status(out uint status, out uint problemNumber, uint devInst, uint flags);

    private static bool TryLocateDevNode(string deviceId, out uint devInst)
    {
        // 1. Try exact deviceId
        if (CM_Locate_DevNode(out devInst, deviceId, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
            return true;

        if (CM_Locate_DevNode(out devInst, deviceId, CM_LOCATE_DEVNODE_PHANTOM) == CR_SUCCESS)
            return true;

        // 2. If without prefix, try common enumerator prefixes
        if (!deviceId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase) &&
            !deviceId.StartsWith("USBSTOR\\", StringComparison.OrdinalIgnoreCase))
        {
            if (CM_Locate_DevNode(out devInst, $@"USBSTOR\{deviceId}", CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS ||
                CM_Locate_DevNode(out devInst, $@"USBSTOR\{deviceId}", CM_LOCATE_DEVNODE_PHANTOM) == CR_SUCCESS ||
                CM_Locate_DevNode(out devInst, $@"USB\{deviceId}", CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS ||
                CM_Locate_DevNode(out devInst, $@"USB\{deviceId}", CM_LOCATE_DEVNODE_PHANTOM) == CR_SUCCESS)
            {
                return true;
            }
        }

        devInst = 0;
        return false;
    }

    public bool IsDevicePresent(string deviceId) => TryLocateDevNode(deviceId, out _);

    public bool DisableDevice(string deviceId)
    {
        if (!TryLocateDevNode(deviceId, out var devInst))
        {
            // Device node not present right now in PnP; durable blocklist still records it
            return false;
        }

        var cr = CM_Disable_DevNode(devInst, 0);
        return cr == CR_SUCCESS;
    }

    public bool EnableDevice(string deviceId)
    {
        if (!TryLocateDevNode(deviceId, out var devInst))
            return false;

        var cr = CM_Enable_DevNode(devInst, 0);
        return cr == CR_SUCCESS;
    }

    public bool IsDeviceDisabled(string deviceId)
    {
        if (!TryLocateDevNode(deviceId, out var devInst))
            return false;

        if (CM_Get_DevNode_Status(out _, out var problemNumber, devInst, 0) == CR_SUCCESS)
            return problemNumber == CM_PROB_DISABLED;

        return false;
    }

    public bool GetUsbStorageEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR");
            if (key != null)
            {
                var startVal = key.GetValue("Start");
                if (startVal is int startInt)
                {
                    return startInt != 4;
                }
            }
        }
        catch { }

        return true;
    }

    public void SetUsbStorageEnabled(bool enabled)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", writable: true);
            if (key is null)
                throw new InvalidOperationException("Failed to open USBSTOR registry service key.");

            key.SetValue("Start", enabled ? 3 : 4, RegistryValueKind.DWord);
        }
        catch (SecurityException ex)
        {
            throw new UnauthorizedAccessException("Administrator privileges required to modify USBSTOR service state.", ex);
        }
    }
}

/// <summary>
/// In-memory USB backend for deterministic testing.
/// </summary>
public sealed class InMemoryUsbDeviceBackend : IUsbDeviceBackend
{
    private readonly HashSet<string> _present = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _disabled = new(StringComparer.OrdinalIgnoreCase);
    private bool _usbStorageEnabled = true;

    public void AddDevice(string deviceId, bool disabled = false)
    {
        _present.Add(deviceId);
        if (disabled) _disabled.Add(deviceId);
    }

    public bool IsDevicePresent(string deviceId) => _present.Contains(deviceId);

    public bool DisableDevice(string deviceId)
    {
        if (!_present.Contains(deviceId)) return false;
        _disabled.Add(deviceId);
        return true;
    }

    public bool EnableDevice(string deviceId)
    {
        if (!_present.Contains(deviceId)) return false;
        _disabled.Remove(deviceId);
        return true;
    }

    public bool IsDeviceDisabled(string deviceId) => _disabled.Contains(deviceId);

    public bool GetUsbStorageEnabled() => _usbStorageEnabled;

    public void SetUsbStorageEnabled(bool enabled) => _usbStorageEnabled = enabled;
}

/// <summary>
/// Executes policy-checked, audited USB device management actions (DN-008 Phase 4).
/// Enforces an immutable deny-list protecting input devices (keyboards, mice, touchpads),
/// host controllers, root hubs, and system boot disks. Manages durable blocked device state
/// and USBSTOR service configuration.
/// </summary>
public sealed class UsbActionExecutor
{
    private static readonly HashSet<string> ProtectedBusPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "PCI\\",
        "ACPI\\",
        "SCSI\\",
        "IDE\\",
        "STORAGE\\",
        "SWD\\"
    };

    private static readonly string[] ProtectedDeviceTerms =
    [
        "Keyboard",
        "Mouse",
        "Pointer",
        "Touchpad",
        "Touch Screen",
        "Trackball",
        "Stylus",
        "ROOT_HUB",
        "RootHub"
    ];

    private readonly IUsbDeviceBackend _backend;
    private readonly string _storePath;
    private readonly object _gate = new();
    private List<BlockedUsbDeviceRecord>? _cachedBlocked;

    public UsbActionExecutor(IUsbDeviceBackend? backend = null, string? storePath = null)
    {
        _backend = backend ?? new WindowsUsbDeviceBackend();
        if (storePath != null)
        {
            _storePath = storePath;
        }
        else
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
            SecureJournalDirectory.Ensure(root);
            _storePath = Path.Combine(root, "blocked-usb-devices.v1.json");
            SecureJournalDirectory.RestrictExistingFile(_storePath);
        }
    }

    public (bool Allowed, string? DenyReason) ValidateDevice(string? deviceId, string? friendlyName)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return (false, "Device ID cannot be null, empty, or whitespace.");

        var trimmed = deviceId.Trim();
        if (trimmed.Length < 3 || trimmed.Length > 256)
            return (false, "Device ID length must be between 3 and 256 characters.");

        if (trimmed.IndexOfAny(['\r', '\n', '\0', '\t']) >= 0)
            return (false, "Device ID contains invalid control characters.");

        // 1. Root Hub protection
        if (trimmed.Contains("ROOT_HUB", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("USB#ROOT_HUB", StringComparison.OrdinalIgnoreCase))
        {
            return (false, "USB Root Hubs cannot be blocked to prevent host bus disconnection.");
        }

        // 2. Host Controllers & Internal System Buses
        foreach (var prefix in ProtectedBusPrefixes)
        {
            if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return (false, $"Internal system bus devices ({prefix.TrimEnd('\\')}) cannot be blocked.");
            }
        }

        // 3. Human Interface Devices (HID) protection (Keyboards, Mice, Touchpads)
        if (trimmed.StartsWith("HID\\", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Contains("&Col0", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Contains("&Col1", StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Human Interface Devices (keyboards, mice, touchpads) are strictly protected to prevent operator lockout.");
        }

        // Check friendly name and device ID for input device terms
        foreach (var term in ProtectedDeviceTerms)
        {
            if (trimmed.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrWhiteSpace(friendlyName) && friendlyName.Contains(term, StringComparison.OrdinalIgnoreCase)))
            {
                return (false, $"Input and system devices matching '{term}' are strictly protected to prevent system lockout.");
            }
        }

        // 4. System / OS Boot Volume protection
        var sysDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\');
        if (!string.IsNullOrEmpty(sysDrive))
        {
            if (trimmed.Equals(sysDrive, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrWhiteSpace(friendlyName) && friendlyName.Contains(sysDrive, StringComparison.OrdinalIgnoreCase)))
            {
                return (false, "The system boot drive volume is strictly protected from blocking.");
            }
        }

        return (true, null);
    }

    public IReadOnlyList<BlockedUsbDeviceRecord> GetBlockedDevices()
    {
        lock (_gate)
        {
            return (_cachedBlocked ??= LoadBlockedList()).AsReadOnly();
        }
    }

    public bool IsDeviceBlocked(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        var trimmed = deviceId.Trim();
        lock (_gate)
        {
            var list = _cachedBlocked ??= LoadBlockedList();
            return list.Any(r => r.DeviceId.Equals(trimmed, StringComparison.OrdinalIgnoreCase));
        }
    }

    public (bool Succeeded, string ResultCode, string Message) BlockDevice(string deviceId, string? friendlyName, string? reason)
    {
        var (allowed, denyReason) = ValidateDevice(deviceId, friendlyName);
        if (!allowed)
            return (false, "denied-protected-device", denyReason ?? "Device is protected.");

        var trimmed = deviceId.Trim();
        lock (_gate)
        {
            var list = _cachedBlocked ??= LoadBlockedList();
            if (list.Any(r => r.DeviceId.Equals(trimmed, StringComparison.OrdinalIgnoreCase)))
            {
                return (true, "already-blocked", $"Device '{trimmed}' is already in the blocked devices list.");
            }

            try
            {
                _backend.DisableDevice(trimmed);
            }
            catch (Exception ex)
            {
                return (false, "disable-failed", $"Failed to disable PnP device node: {ex.Message}");
            }

            list.Add(new BlockedUsbDeviceRecord(trimmed, friendlyName?.Trim(), DateTimeOffset.UtcNow, reason?.Trim()));
            SaveBlockedList(list);
        }

        return (true, "blocked", $"Device '{trimmed}' has been blocked and disabled.");
    }

    public (bool Succeeded, string ResultCode, string Message) UnblockDevice(string deviceId, string? friendlyName)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return (false, "invalid-device-id", "Device ID cannot be null or empty.");

        var trimmed = deviceId.Trim();
        lock (_gate)
        {
            var list = _cachedBlocked ??= LoadBlockedList();
            var existing = list.FirstOrDefault(r => r.DeviceId.Equals(trimmed, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                // Not in our blocklist, but try re-enabling PnP device anyway
                try
                {
                    _backend.EnableDevice(trimmed);
                }
                catch { }

                return (true, "not-blocked", $"Device '{trimmed}' was not in the blocked list.");
            }

            try
            {
                _backend.EnableDevice(trimmed);
            }
            catch (Exception ex)
            {
                return (false, "enable-failed", $"Failed to re-enable PnP device node: {ex.Message}");
            }

            list.Remove(existing);
            SaveBlockedList(list);
        }

        return (true, "unblocked", $"Device '{trimmed}' has been unblocked and re-enabled.");
    }

    public bool GetUsbStorageEnabled() => _backend.GetUsbStorageEnabled();

    public (bool Succeeded, string ResultCode, string Message) SetUsbStorage(bool enabled, string? reason)
    {
        try
        {
            _backend.SetUsbStorageEnabled(enabled);
            var stateStr = enabled ? "enabled" : "disabled";
            return (true, "updated", $"USB mass storage service (USBSTOR) has been {stateStr}.");
        }
        catch (UnauthorizedAccessException ex)
        {
            return (false, "denied-permission", ex.Message);
        }
        catch (Exception ex)
        {
            return (false, "update-failed", $"Failed to update USBSTOR service: {ex.Message}");
        }
    }

    private List<BlockedUsbDeviceRecord> LoadBlockedList()
    {
        try
        {
            if (File.Exists(_storePath))
            {
                var bytes = File.ReadAllBytes(_storePath);
                var records = JsonSerializer.Deserialize<List<BlockedUsbDeviceRecord>>(bytes);
                if (records != null) return records;
            }
        }
        catch { }

        return [];
    }

    private void SaveBlockedList(List<BlockedUsbDeviceRecord> records)
    {
        var temp = _storePath + ".tmp";
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(records, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllBytes(temp, bytes);
            File.Move(temp, _storePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(temp); } catch { }
        }
    }
}
