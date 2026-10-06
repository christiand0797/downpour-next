using System.Diagnostics;
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
        wifiAvailable = false;
        connectedSsid = null;
        connectedBssid = null;

        var netshPath = Path.Combine(Environment.SystemDirectory, "netsh.exe");
        if (!File.Exists(netshPath))
        {
            warnings.Add("netsh.exe was not found in System directory.");
            return;
        }

        // 1. Check interfaces
        var (ifaceExit, ifaceOut, _) = RunCommand(netshPath, "wlan show interfaces", 5);
        if (ifaceExit == 0 && !string.IsNullOrWhiteSpace(ifaceOut))
        {
            if (ifaceOut.Contains("There is 0 interface", StringComparison.OrdinalIgnoreCase) ||
                ifaceOut.Contains("There is no wireless interface", StringComparison.OrdinalIgnoreCase))
            {
                wifiAvailable = false;
            }
            else
            {
                wifiAvailable = true;

                // Check connection state
                var lines = ifaceOut.Split(["\r\n", "\r", "\n"], StringSplitOptions.RemoveEmptyEntries);
                var isConnected = false;
                foreach (var rawLine in lines)
                {
                    var line = rawLine.Trim();
                    if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase) &&
                        line.Contains("connected", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("disconnected", StringComparison.OrdinalIgnoreCase))
                    {
                        isConnected = true;
                    }
                    else if (line.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) &&
                             !line.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(':', 2);
                        if (parts.Length == 2)
                        {
                            connectedSsid = parts[1].Trim();
                        }
                    }
                    else if (line.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(':', 2);
                        if (parts.Length == 2)
                        {
                            connectedBssid = parts[1].Trim();
                        }
                    }
                }

                if (!isConnected)
                {
                    connectedSsid = null;
                    connectedBssid = null;
                }
            }
        }
        else
        {
            warnings.Add("WLAN interface query did not return successfully.");
        }

        // 2. Scan visible networks
        var (netExit, netOut, netErr) = RunCommand(netshPath, "wlan show networks mode=bssid", 8);
        if (netExit == 0 && !string.IsNullOrWhiteSpace(netOut))
        {
            ParseNetworks(netOut, networks, connectedSsid, connectedBssid);
        }
        else if (!string.IsNullOrWhiteSpace(netErr))
        {
            warnings.Add($"WLAN network scan: {Truncate(netErr.Trim(), 128)}");
        }
        else if (wifiAvailable)
        {
            warnings.Add("WLAN network scan returned no visible networks or radio is disabled.");
        }
    }

    private static void ParseNetworks(
        string netshOutput,
        List<WifiNetworkEntry> networks,
        string? connectedSsid,
        string? connectedBssid)
    {
        var lines = netshOutput.Split(["\r\n", "\r", "\n"], StringSplitOptions.None);
        var currentSsid = "";
        var currentNetType = "Infrastructure";
        var currentAuth = "Unknown";
        var currentCipher = "Unknown";

        for (var i = 0; i < lines.Length; i++)
        {
            if (networks.Count >= MaximumNetworks) break;

            var line = lines[i].Trim();
            if (line.StartsWith("SSID ", StringComparison.OrdinalIgnoreCase) && !line.Contains("BSSID", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                currentSsid = parts.Length == 2 ? parts[1].Trim() : "";
            }
            else if (line.StartsWith("Network type", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                currentNetType = parts.Length == 2 ? parts[1].Trim() : "Infrastructure";
            }
            else if (line.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                currentAuth = parts.Length == 2 ? parts[1].Trim() : "Unknown";
            }
            else if (line.StartsWith("Encryption", StringComparison.OrdinalIgnoreCase) ||
                     line.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                currentCipher = parts.Length == 2 ? parts[1].Trim() : "Unknown";
            }
            else if (line.StartsWith("BSSID ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                var bssid = parts.Length == 2 ? parts[1].Trim() : "";
                var signal = 0;
                var channel = 0;

                // Read next few lines for Signal and Channel
                while (i + 1 < lines.Length && !lines[i + 1].Trim().StartsWith("BSSID ", StringComparison.OrdinalIgnoreCase) &&
                       !lines[i + 1].Trim().StartsWith("SSID ", StringComparison.OrdinalIgnoreCase))
                {
                    i++;
                    var subLine = lines[i].Trim();
                    if (subLine.StartsWith("Signal", StringComparison.OrdinalIgnoreCase))
                    {
                        var m = Regex.Match(subLine, @"(\d+)%");
                        if (m.Success && int.TryParse(m.Groups[1].Value, out var s))
                            signal = s;
                    }
                    else if (subLine.StartsWith("Channel", StringComparison.OrdinalIgnoreCase))
                    {
                        var m = Regex.Match(subLine, @"(\d+)");
                        if (m.Success && int.TryParse(m.Groups[1].Value, out var c))
                            channel = c;
                    }
                }

                var isConnected = (!string.IsNullOrEmpty(connectedBssid) && string.Equals(bssid, connectedBssid, StringComparison.OrdinalIgnoreCase))
                    || (!string.IsNullOrEmpty(connectedSsid) && string.Equals(currentSsid, connectedSsid, StringComparison.OrdinalIgnoreCase));

                networks.Add(new WifiNetworkEntry(
                    Ssid: Truncate(currentSsid, 128),
                    Bssid: Truncate(bssid, 32),
                    SignalPercent: Math.Clamp(signal, 0, 100),
                    Authentication: Truncate(currentAuth, 64),
                    Cipher: Truncate(currentCipher, 32),
                    Channel: channel,
                    NetworkType: Truncate(currentNetType, 32),
                    IsConnected: isConnected));
            }
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

    private static (int exitCode, string stdout, string stderr) RunCommand(string file, string args, int timeoutSeconds)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = file,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                }
            };

            proc.Start();
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            if (proc.WaitForExit(timeoutSeconds * 1000))
            {
                return (proc.ExitCode, stdout, stderr);
            }

            try { proc.Kill(); } catch { }
            return (-1, stdout, "Command timed out");
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Length <= max ? value : value[..max];
    }
}
