using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>A device that needs attention, with what is wrong and what to do about it.</summary>
public sealed record DeviceProblem(DeviceEntry Device, string Severity, string Title, string Explanation, string Fix, bool MissingDriver);

/// <summary>
/// Explains Device Manager problem codes (CM_PROB_*) in plain words with a concrete fix, finds devices without a
/// working driver, and matches Windows Update driver offers to devices by hardware ID or model.
/// </summary>
public static class DeviceAnalyzer
{
    private static readonly Dictionary<int, (string Title, string Explanation, string Fix, bool Missing)> Codes = new()
    {
        [1] = ("Not configured correctly", "Windows could not configure the device (code 1).", "Update the driver from Windows Update or the maker's site.", false),
        [3] = ("Driver may be damaged", "The driver may be corrupted or the PC is low on memory (code 3).", "Reinstall the driver from Device Manager (uninstall, then scan for hardware changes).", false),
        [10] = ("Cannot start", "The device failed to start (code 10), usually an incompatible or outdated driver.", "Update or roll back the driver.", false),
        [12] = ("Resource conflict", "Not enough free resources for this device (code 12).", "Disable a conflicting device or update firmware/BIOS.", false),
        [14] = ("Restart needed", "The device needs a restart to work (code 14).", "Restart the PC.", false),
        [18] = ("Reinstall drivers", "The drivers need to be reinstalled (code 18).", "Reinstall the driver from Device Manager.", false),
        [19] = ("Bad registry configuration", "Configuration information in the registry is incomplete or damaged (code 19).", "Uninstall the device in Device Manager and scan for hardware changes.", false),
        [21] = ("Being removed", "Windows is removing this device (code 21).", "Restart the PC.", false),
        [22] = ("Disabled", "The device is disabled (code 22).", "Enable it in Device Manager if you need it.", false),
        [24] = ("Not present or no driver", "The device is not present, not working properly, or has no driver (code 24).", "Reconnect it, or install its driver.", true),
        [28] = ("Driver not installed", "No driver is installed for this device (code 28).", "Search Windows Update for a driver, or install one from the maker's site.", true),
        [29] = ("Disabled by firmware", "The firmware did not give the device resources (code 29).", "Enable it in the BIOS/UEFI settings.", false),
        [31] = ("Driver could not load", "Windows could not load the drivers this device needs (code 31).", "Update or reinstall the driver.", true),
        [32] = ("Driver service disabled", "The driver service is disabled (code 32).", "Reinstall the driver.", false),
        [33] = ("Cannot determine resources", "Windows cannot determine which resources it needs (code 33).", "Check hardware or update firmware.", false),
        [35] = ("Firmware missing information", "The firmware lacks information for this device (code 35).", "Update the BIOS/UEFI from the PC maker.", false),
        [37] = ("Driver failed to initialize", "The driver returned a failure when it started (code 37).", "Reinstall or update the driver.", false),
        [38] = ("Previous driver still in memory", "A previous instance of the driver is still in memory (code 38).", "Restart the PC.", false),
        [39] = ("Driver corrupted or missing", "Windows cannot load the driver; it may be corrupted or missing (code 39).", "Reinstall the driver.", true),
        [40] = ("Registry service key damaged", "Windows cannot access this hardware because its service key is damaged (code 40).", "Reinstall the driver.", false),
        [41] = ("Hardware not found", "The driver loaded but cannot find the hardware (code 41).", "Reconnect the hardware or reinstall the driver.", false),
        [43] = ("Device reported a problem", "Windows stopped the device because it reported problems (code 43).", "Update the driver; if it continues, the hardware may be failing.", false),
        [45] = ("Not connected", "The device is not currently connected (code 45).", "Reconnect it if you use it.", false),
        [47] = ("Prepared for safe removal", "The device was prepared for safe removal (code 47).", "Unplug and plug it back in.", false),
        [48] = ("Blocked driver", "The driver was blocked because it has known problems (code 48), sometimes by the vulnerable-driver blocklist.", "Get an updated driver from the maker.", false),
        [52] = ("Signature not verified", "Windows cannot verify the driver's digital signature (code 52).", "Install a properly signed driver; an unsigned driver can be a security risk.", false),
    };

    public static DeviceProblem? Problem(DeviceEntry device)
    {
        if (device.ProblemCode is 0 && !string.IsNullOrEmpty(device.DriverProvider)) return null;
        if (device.ProblemCode is 0)
            return device.Present && string.IsNullOrEmpty(device.InfName) && device.Status.Equals("Error", StringComparison.OrdinalIgnoreCase)
                ? new DeviceProblem(device, "MEDIUM", "No driver", "The device has no driver bound to it.", "Search Windows Update for a driver.", true)
                : null;
        if (!device.Present && device.ProblemCode is 45 or 24) return null; // devices simply not plugged in are not problems
        if (Codes.TryGetValue(device.ProblemCode, out var known))
            return new DeviceProblem(device, device.ProblemCode is 22 or 45 or 47 or 14 ? "LOW" : device.ProblemCode is 52 or 48 ? "HIGH" : "MEDIUM",
                known.Title, known.Explanation, known.Fix, known.Missing);
        return new DeviceProblem(device, "MEDIUM", $"Problem code {device.ProblemCode}", $"Device Manager reports problem code {device.ProblemCode}.",
            "Open the device in Device Manager for details.", false);
    }

    public static IReadOnlyList<DeviceProblem> Problems(IEnumerable<DeviceEntry> devices) =>
        devices.Select(Problem).OfType<DeviceProblem>()
            .OrderBy(p => p.Severity switch { "HIGH" => 0, "MEDIUM" => 1, _ => 2 })
            .ThenByDescending(p => p.MissingDriver)
            .ThenBy(p => p.Device.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    /// <summary>The installed devices a Windows Update driver offer applies to (by hardware ID, then by model name).</summary>
    public static IReadOnlyList<DeviceEntry> Targets(DriverUpdateOffer offer, IEnumerable<DeviceEntry> devices)
    {
        var all = devices.ToArray();
        if (offer.DriverHardwareId is { Length: > 0 } id)
        {
            var byId = all.Where(d => d.HardwareId is { } hw && hw.StartsWith(id, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (byId.Length > 0) return byId;
        }
        return offer.DriverModel is { Length: > 2 } model
            ? all.Where(d => d.Name.Equals(model, StringComparison.OrdinalIgnoreCase)).ToArray()
            : [];
    }

    /// <summary>Driver age in whole years (for the age chart); null when the date is unknown.</summary>
    public static int? AgeYears(DeviceEntry device, DateTimeOffset now) =>
        device.DriverDate is { } date && date.Year > 1990 ? Math.Max(0, (int)((now - date).TotalDays / 365.25)) : null;
}
