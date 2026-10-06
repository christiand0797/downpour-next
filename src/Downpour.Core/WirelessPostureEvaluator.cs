using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

public static class WirelessPostureEvaluator
{
    private const string SniffingTechnique = "T1040";
    private const string MitmTechnique = "T1557.002";
    private const string HardwareTechnique = "T1200";
    private const string BtExfilTechnique = "T1011.001";
    private const int MaximumFindings = 128;

    private static readonly Regex[] SuspiciousSsidPatterns =
    [
        new(@"^free[\s_-]?wifi", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"^open[\s_-]?network", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"^guest[\s_-]?wifi[\s_-]?free", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"^airport[\s_-]?wifi", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"^starbucks[\s_-]?wifi", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"^hotel[\s_-]?wifi", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"^setup|^config|^admin", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"^hack|^pwn|^evil|^rogue", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"pineapple", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"flipper", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    private static readonly Dictionary<string, string> AttackToolOuis = new(StringComparer.OrdinalIgnoreCase)
    {
        ["00:13:37"] = "Hak5 WiFi Pineapple",
        ["AA:BB:CC"] = "Common spoofed OUI",
        ["00:11:22"] = "Common spoofed OUI",
        ["DE:AD:BE"] = "Common spoofed OUI pattern"
    };

    private static readonly Regex[] SuspiciousBtNames =
    [
        new(@"^hack|^pwn|^evil|^rogue", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"flipper|ubertooth|bluehydra", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"scanner|sniffer|intercept|keylog", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"pineapple", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    public static IReadOnlyList<WirelessFinding> Analyze(
        bool wifiAvailable,
        string? connectedSsid,
        string? connectedBssid,
        bool bluetoothEnabled,
        IReadOnlyList<WifiNetworkEntry> networks,
        IReadOnlyList<BluetoothDeviceEntry> btDevices)
    {
        var findings = new List<WirelessFinding>();

        // Connected network checks
        var connected = networks.FirstOrDefault(n => n.IsConnected ||
            (!string.IsNullOrEmpty(connectedSsid) && string.Equals(n.Ssid, connectedSsid, StringComparison.OrdinalIgnoreCase)));

        if (connected != null)
        {
            if (IsWeakAuth(connected.Authentication))
            {
                findings.Add(new WirelessFinding(
                    "HIGH",
                    SniffingTechnique,
                    $"Currently connected Wi-Fi network '{connected.Ssid}' uses weak or unencrypted authentication ({connected.Authentication}). Traffic is subject to eavesdropping.",
                    $"Connected:{connected.Ssid}:{connected.Authentication}"));
            }
        }

        // Visible network checks & evil twin analysis
        var networksBySsid = networks
            .Where(n => !string.IsNullOrWhiteSpace(n.Ssid))
            .GroupBy(n => n.Ssid, StringComparer.OrdinalIgnoreCase);

        foreach (var group in networksBySsid)
        {
            if (findings.Count >= MaximumFindings) break;

            var list = group.ToList();

            // Evil Twin check: same SSID broadcast with differing security levels
            if (list.Count > 1)
            {
                var hasSecure = list.Any(n => !IsWeakAuth(n.Authentication));
                var hasInsecure = list.Any(n => IsWeakAuth(n.Authentication));
                if (hasSecure && hasInsecure)
                {
                    findings.Add(new WirelessFinding(
                        "CRITICAL",
                        MitmTechnique,
                        $"Possible Evil Twin attack: SSID '{group.Key}' has multiple BSSIDs with conflicting security configurations (secure vs open/weak).",
                        $"EvilTwin:{group.Key}"));
                }
            }

            foreach (var net in list)
            {
                if (findings.Count >= MaximumFindings) break;

                // Suspicious SSID patterns
                foreach (var pattern in SuspiciousSsidPatterns)
                {
                    if (pattern.IsMatch(net.Ssid))
                    {
                        findings.Add(new WirelessFinding(
                            "HIGH",
                            MitmTechnique,
                            $"Suspicious or spoofed SSID name pattern detected: '{net.Ssid}' (BSSID: {net.Bssid}).",
                            $"{net.Bssid}:{net.Ssid}"));
                        break;
                    }
                }

                // Attack tool OUI
                if (net.Bssid.Length >= 8)
                {
                    var oui = net.Bssid[..8].Replace('-', ':');
                    if (AttackToolOuis.TryGetValue(oui, out var toolName))
                    {
                        findings.Add(new WirelessFinding(
                            "CRITICAL",
                            HardwareTechnique,
                            $"Known attack tool MAC address prefix detected on '{net.Ssid}': {toolName} ({net.Bssid}).",
                            $"{net.Bssid}:{toolName}"));
                    }
                }

                // Visible weak auth warning
                if (!net.IsConnected && IsWeakAuth(net.Authentication))
                {
                    findings.Add(new WirelessFinding(
                        "LOW",
                        SniffingTechnique,
                        $"Open or unencrypted Wi-Fi network nearby: '{net.Ssid}' (BSSID: {net.Bssid}). Potential honeypot.",
                        $"{net.Bssid}:OpenNetwork"));
                }
            }
        }

        // Bluetooth checks
        foreach (var device in btDevices)
        {
            if (findings.Count >= MaximumFindings) break;

            foreach (var pattern in SuspiciousBtNames)
            {
                if (pattern.IsMatch(device.Name))
                {
                    findings.Add(new WirelessFinding(
                        "HIGH",
                        BtExfilTechnique,
                        $"Suspicious Bluetooth device name pattern in paired devices: '{device.Name}' ({device.Address}).",
                        $"{device.Address}:{device.Name}"));
                    break;
                }
            }
        }

        return findings;
    }

    private static bool IsWeakAuth(string auth) =>
        auth.Equals("Open", StringComparison.OrdinalIgnoreCase) ||
        auth.Equals("None", StringComparison.OrdinalIgnoreCase) ||
        auth.Equals("WEP", StringComparison.OrdinalIgnoreCase) ||
        auth.Equals("Shared", StringComparison.OrdinalIgnoreCase);
}
