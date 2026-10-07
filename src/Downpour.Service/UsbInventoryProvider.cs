using System.Management;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

public sealed class UsbInventoryProvider
{
    private const int MaximumConnected = 64;
    private const int MaximumHistory = 512;
    private const int MaximumText = 512;

    /// <summary>
    /// Maps a drive letter to the PnP instance ID of the USB storage function behind it (logical disk -> partition ->
    /// disk drive) through documented WMI associations. Returns null for anything that is not a USBSTOR device, so a
    /// block can only ever target a USB storage function.
    /// </summary>
    internal static string? ResolveStorageInstanceId(string driveLetter)
    {
        var letter = driveLetter.TrimEnd('\\');
        if (letter.Length != 2 || !char.IsAsciiLetter(letter[0]) || letter[1] != ':') return null;
        try
        {
            var options = new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(5), ReturnImmediately = false };
            using var partitions = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"),
                new ObjectQuery($"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{letter}'}} WHERE AssocClass=Win32_LogicalDiskToPartition"), options);
            foreach (var partition in partitions.Get())
            {
                using (partition)
                {
                    if (partition["DeviceID"] is not string partitionId || partitionId.Contains('\'')) continue;
                    using var disks = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"),
                        new ObjectQuery($"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partitionId}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition"), options);
                    foreach (var disk in disks.Get())
                    {
                        using (disk)
                        {
                            if (disk["PNPDeviceID"] is string pnp && pnp.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase) && pnp.Length <= 256)
                                return pnp;
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or System.Runtime.InteropServices.COMException or UnauthorizedAccessException or TimeoutException)
        {
            // Unknown device identity: the UI hides the block action rather than guessing.
        }
        return null;
    }

    private static readonly string[] AutorunFilenames =
    [
        "autorun.inf",
        "autorun.bat",
        "autorun.exe",
        "autorun.com"
    ];

    private static readonly string[] SuspiciousExtensions =
    [
        ".scr",
        ".pif",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".ps1"
    ];

    public UsbSnapshot Capture()
    {
        var warnings = new List<string>();
        var connectedDevices = new List<UsbConnectedDevice>();
        var history = new List<UsbDeviceHistoryEntry>();

        var usbStorageEnabled = IsUsbStorageEnabled(warnings);
        CollectConnectedDevices(connectedDevices, warnings);
        CollectDeviceHistory(history, warnings);

        var findings = UsbPostureEvaluator.Analyze(usbStorageEnabled, connectedDevices, history);

        return new UsbSnapshot(
            SchemaVersion: 1,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            UsbStorageServiceEnabled: usbStorageEnabled,
            ConnectedDevices: connectedDevices,
            History: history,
            Findings: findings,
            Warnings: warnings);
    }

    private static bool IsUsbStorageEnabled(List<string> warnings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR");
            if (key != null)
            {
                var startVal = key.GetValue("Start");
                if (startVal is int startInt)
                {
                    // 4 means disabled; 2 is Automatic, 3 is Manual/Demand
                    return startInt != 4;
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to inspect USBSTOR service registry state: {Truncate(ex.Message, 128)}");
        }

        return true;
    }

    private static void CollectConnectedDevices(List<UsbConnectedDevice> connectedDevices, List<string> warnings)
    {
        try
        {
            var drives = DriveInfo.GetDrives();
            foreach (var drive in drives)
            {
                if (connectedDevices.Count >= MaximumConnected) break;
                if (!drive.IsReady) continue;

                // Inspect removable drives
                if (drive.DriveType != DriveType.Removable) continue;

                var letter = drive.Name.TrimEnd('\\');
                var label = Truncate(drive.VolumeLabel, 64);
                var format = Truncate(drive.DriveFormat, 32);
                var totalBytes = drive.TotalSize;
                var freeBytes = drive.AvailableFreeSpace;
                var hasAutorun = false;
                var hasSuspicious = false;

                try
                {
                    var root = drive.RootDirectory.FullName;
                    foreach (var autorunFile in AutorunFilenames)
                    {
                        if (File.Exists(Path.Combine(root, autorunFile)))
                        {
                            hasAutorun = true;
                            break;
                        }
                    }

                    // Check top-level files for suspicious executables/scripts
                    var topFiles = Directory.EnumerateFiles(root).Take(50);
                    foreach (var file in topFiles)
                    {
                        var ext = Path.GetExtension(file);
                        if (SuspiciousExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
                        {
                            hasSuspicious = true;
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    warnings.Add($"Permission or I/O error checking root of {letter}: {Truncate(ex.Message, 128)}");
                }

                connectedDevices.Add(new UsbConnectedDevice(
                    DriveLetter: letter,
                    VolumeLabel: string.IsNullOrEmpty(label) ? "Removable Disk" : label,
                    FileSystem: string.IsNullOrEmpty(format) ? "Unknown" : format,
                    TotalSizeBytes: totalBytes,
                    FreeSizeBytes: freeBytes,
                    Vendor: "Removable",
                    Product: "USB Drive",
                    SerialNumber: "Unknown",
                    HasAutorun: hasAutorun,
                    HasSuspiciousFiles: hasSuspicious,
                    DriveType: drive.DriveType.ToString(),
                    PnpDeviceId: ResolveStorageInstanceId(letter)));
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to enumerate drives: {Truncate(ex.Message, 128)}");
        }
    }

    private static void CollectDeviceHistory(List<UsbDeviceHistoryEntry> history, List<string> warnings)
    {
        // 1. Check USBSTOR registry entries
        try
        {
            using var usbstorKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (usbstorKey != null)
            {
                foreach (var deviceSubKey in usbstorKey.GetSubKeyNames())
                {
                    if (history.Count >= MaximumHistory) break;
                    using var devKey = usbstorKey.OpenSubKey(deviceSubKey);
                    if (devKey == null) continue;

                    // Parse Vendor/Product/Rev from key name: Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00
                    var parts = deviceSubKey.Split('&');
                    var vendor = parts.FirstOrDefault(p => p.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase))?[4..] ?? "";
                    var product = parts.FirstOrDefault(p => p.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase))?[5..] ?? "";
                    var rev = parts.FirstOrDefault(p => p.StartsWith("Rev_", StringComparison.OrdinalIgnoreCase))?[4..] ?? "";

                    foreach (var instanceSubKey in devKey.GetSubKeyNames())
                    {
                        if (history.Count >= MaximumHistory) break;
                        using var instKey = devKey.OpenSubKey(instanceSubKey);
                        if (instKey == null) continue;

                        var friendlyName = instKey.GetValue("FriendlyName")?.ToString()
                            ?? instKey.GetValue("DeviceDesc")?.ToString()
                            ?? deviceSubKey;
                        var hardwareId = instKey.GetValue("HardwareID") switch
                        {
                            string[] ids => string.Join(", ", ids),
                            string s => s,
                            _ => ""
                        };

                        // Full PnP instance ID (USBSTOR\<device>\<serial>) so a block targets exactly this device.
                        history.Add(new UsbDeviceHistoryEntry(
                            DeviceId: Truncate($@"USBSTOR\{deviceSubKey}\{instanceSubKey}", 256),
                            Vendor: Truncate(vendor, 64),
                            Product: Truncate(product, 64),
                            Revision: Truncate(rev, 32),
                            SerialNumber: Truncate(instanceSubKey, 128),
                            FriendlyName: Truncate(friendlyName, 256),
                            HardwareId: Truncate(hardwareId, 256)));
                    }
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to read USBSTOR history: {Truncate(ex.Message, 128)}");
        }

        // 2. Check USB registry entries for additional USB devices
        try
        {
            using var usbKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
            if (usbKey != null)
            {
                foreach (var deviceSubKey in usbKey.GetSubKeyNames())
                {
                    if (history.Count >= MaximumHistory) break;
                    if (deviceSubKey.StartsWith("ROOT_HUB", StringComparison.OrdinalIgnoreCase)) continue;

                    using var devKey = usbKey.OpenSubKey(deviceSubKey);
                    if (devKey == null) continue;

                    foreach (var instanceSubKey in devKey.GetSubKeyNames())
                    {
                        if (history.Count >= MaximumHistory) break;
                        using var instKey = devKey.OpenSubKey(instanceSubKey);
                        if (instKey == null) continue;

                        var friendlyName = instKey.GetValue("FriendlyName")?.ToString()
                            ?? instKey.GetValue("DeviceDesc")?.ToString()
                            ?? deviceSubKey;

                        var hardwareId = instKey.GetValue("HardwareID") switch
                        {
                            string[] ids => string.Join(", ", ids),
                            string s => s,
                            _ => ""
                        };

                        // Avoid listing a storage device twice (its USB parent shares the serial).
                        if (history.Any(h => h.SerialNumber == instanceSubKey)) continue;

                        history.Add(new UsbDeviceHistoryEntry(
                            DeviceId: Truncate($@"USB\{deviceSubKey}\{instanceSubKey}", 256),
                            Vendor: Truncate(deviceSubKey, 64),
                            Product: Truncate(deviceSubKey, 64),
                            Revision: "",
                            SerialNumber: Truncate(instanceSubKey, 128),
                            FriendlyName: Truncate(friendlyName, 256),
                            HardwareId: Truncate(hardwareId, 256)));
                    }
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to read USB device history: {Truncate(ex.Message, 128)}");
        }
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max];
    }
}
