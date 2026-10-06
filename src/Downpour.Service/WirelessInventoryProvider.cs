using System.Text;
using System.Text.RegularExpressions;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

public sealed class WirelessInventoryProvider
{
    private const int MaximumNetworks = 128;
    private const int MaximumBtDevices = 128;
    private const int MaximumWarnings = 64;

    private static readonly Regex BtSuspiciousPattern = new(
        @"(?i)flipper|ubertooth|bluehydra|scanner|sniffer|keylog|pineapple|hack|pwn|evil|rogue",
        RegexOptions.Compiled);

    public WirelessSnapshot Capture()
    {
        var warnings = new List<string>();
        var networks = new List<WifiNetworkEntry>();
        var btDevices = new List<BluetoothDeviceEntry>();

        CollectWifi(out var wifiAvailable, out var connectedSsid, out var connectedBssid, networks, warnings);
        CollectBluetooth(out var btEnabled, btDevices, warnings);

        var findings = WirelessPostureEvaluator.Analyze(
            wifiAvailable,
            connectedSsid,
            connectedBssid,
            btEnabled,
            networks,
            btDevices);

        return new WirelessSnapshot(
            SchemaVersion: 1,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            WifiAdapterAvailable: wifiAvailable,
            ConnectedSsid: connectedSsid,
            ConnectedBssid: connectedBssid,
            BluetoothAdapterEnabled: btEnabled,
            WifiNetworks: networks,
            BluetoothDevices: btDevices,
            Findings: findings,
            Warnings: warnings);
    }

    private static void CollectWifi(
        out bool wifiAvailable,
        out string? connectedSsid,
        out string? connectedBssid,
        List<WifiNetworkEntry> networks,
        List<string> warnings)
    {
        try
        {
            (wifiAvailable, connectedSsid, connectedBssid) = WlanNative.Collect(networks, warnings, MaximumNetworks);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Server SKUs without the Wireless LAN feature do not ship wlanapi.dll.
            warnings.Add("The Native Wifi API is not installed on this system.");
            (wifiAvailable, connectedSsid, connectedBssid) = (false, null, null);
        }
    }

    private static void CollectBluetooth(
        out bool bluetoothEnabled,
        List<BluetoothDeviceEntry> devices,
        List<string> warnings)
    {
        bluetoothEnabled = false;

        // 1. Check Bluetooth service/parameters
        try
        {
            using var paramKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters");
            if (paramKey != null)
            {
                var disabled = paramKey.GetValue("ServicesDisabled");
                bluetoothEnabled = !(disabled is int d && d == 1);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to inspect Bluetooth adapter registry state: {Truncate(ex.Message, 128)}");
        }

        // 2. Enumerate paired Bluetooth devices from registry
        try
        {
            using var devicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
            if (devicesKey != null)
            {
                foreach (var rawAddr in devicesKey.GetSubKeyNames())
                {
                    if (devices.Count >= MaximumBtDevices) break;

                    using var devKey = devicesKey.OpenSubKey(rawAddr);
                    if (devKey == null) continue;

                    var name = ExtractBluetoothDeviceName(devKey);
                    var formattedAddr = FormatMacAddress(rawAddr);
                    var isSuspicious = BtSuspiciousPattern.IsMatch(name);

                    devices.Add(new BluetoothDeviceEntry(
                        Address: formattedAddr,
                        Name: Truncate(name, 128),
                        RegistryPath: Truncate(@$"HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices\{rawAddr}", 256),
                        IsSuspicious: isSuspicious));
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Failed to read paired Bluetooth devices: {Truncate(ex.Message, 128)}");
        }
    }

    private static string ExtractBluetoothDeviceName(RegistryKey key)
    {
        // Try FriendlyName first, then Name
        var val = key.GetValue("FriendlyName") ?? key.GetValue("Name");
        if (val is string str && !string.IsNullOrWhiteSpace(str))
            return str;

        if (val is byte[] bytes && bytes.Length > 0)
        {
            var text = Encoding.UTF8.GetString(bytes).TrimEnd('\0').Trim();
            if (!string.IsNullOrEmpty(text))
                return text;
        }

        return "Unknown Bluetooth Device";
    }

    private static string FormatMacAddress(string raw)
    {
        if (raw.Length == 12 && Regex.IsMatch(raw, "^[0-9a-fA-F]{12}$"))
        {
            return string.Join(":", Enumerable.Range(0, 6).Select(i => raw.Substring(i * 2, 2)));
        }
        return raw;
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max];
    }
}
