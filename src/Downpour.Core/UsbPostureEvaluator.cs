using Downpour.Contracts;

namespace Downpour.Core;

public static class UsbPostureEvaluator
{
    private const string UsbTechnique = "T1091";
    private const string HardwareTechnique = "T1200";
    private const int MaximumFindings = 128;

    private static readonly string[] SuspiciousDevicePatterns =
    [
        "rubber ducky",
        "badusb",
        "flipper",
        "teensy",
        "maltronics",
        "bash bunny",
        "omg cable",
        "o.mg cable",
        "o.mg"
    ];

    public static IReadOnlyList<UsbFinding> Analyze(
        bool usbStorageServiceEnabled,
        IReadOnlyList<UsbConnectedDevice> connectedDevices,
        IReadOnlyList<UsbDeviceHistoryEntry> history)
    {
        var findings = new List<UsbFinding>();

        if (!usbStorageServiceEnabled)
        {
            findings.Add(new UsbFinding(
                "LOW",
                HardwareTechnique,
                "USB mass storage driver (USBSTOR) is disabled in system policy.",
                "USBSTOR:Disabled"));
        }

        foreach (var device in connectedDevices)
        {
            if (findings.Count >= MaximumFindings) break;

            if (device.HasAutorun)
            {
                findings.Add(new UsbFinding(
                    "HIGH",
                    UsbTechnique,
                    $"Autorun file detected on connected drive {device.DriveLetter} ({device.VolumeLabel}).",
                    $"{device.DriveLetter}:autorun"));
            }

            if (device.HasSuspiciousFiles)
            {
                findings.Add(new UsbFinding(
                    "MEDIUM",
                    UsbTechnique,
                    $"Suspicious standalone executable or script detected in root of {device.DriveLetter}.",
                    $"{device.DriveLetter}:suspicious_root_files"));
            }
        }

        foreach (var entry in history)
        {
            if (findings.Count >= MaximumFindings) break;

            var desc = $"{entry.FriendlyName} {entry.Vendor} {entry.Product} {entry.HardwareId}".ToLowerInvariant();
            foreach (var pattern in SuspiciousDevicePatterns)
            {
                if (desc.Contains(pattern))
                {
                    findings.Add(new UsbFinding(
                        "CRITICAL",
                        HardwareTechnique,
                        $"Suspicious attack-tool hardware signature in USB device history: {entry.FriendlyName} ({pattern}).",
                        $"{entry.DeviceId}:{pattern}"));
                    break;
                }
            }
        }

        return findings;
    }
}
