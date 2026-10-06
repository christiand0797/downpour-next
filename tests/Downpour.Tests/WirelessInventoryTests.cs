using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class WirelessInventoryTests
{
    [Fact]
    public void CleanSecureWirelessGeneratesNoFindings()
    {
        var networks = new List<WifiNetworkEntry>
        {
            new("SecureHomeWifi", "00:24:D7:11:22:33", 85, "WPA2-Personal", "CCMP", 6, "Infrastructure", true),
            new("Office_5G", "10:05:01:44:55:66", 70, "WPA3-Personal", "GCMP", 36, "Infrastructure", false)
        };
        var btDevices = new List<BluetoothDeviceEntry>
        {
            new("00:42:79:E6:D7:FA", "JBL Xtreme 2", "HKLM\\...\\Devices\\004279e6d7fa", false)
        };

        var findings = WirelessPostureEvaluator.Analyze(true, "SecureHomeWifi", "00:24:D7:11:22:33", true, networks, btDevices);
        Assert.Empty(findings);
    }

    [Theory]
    [InlineData("Open")]
    [InlineData("None")]
    [InlineData("WEP")]
    [InlineData("Shared")]
    public void ConnectedWeakAuthenticationGeneratesHighFinding(string weakAuth)
    {
        var networks = new List<WifiNetworkEntry>
        {
            new("CoffeeShop", "02:11:22:33:44:55", 90, weakAuth, "None", 1, "Infrastructure", true)
        };

        var findings = WirelessPostureEvaluator.Analyze(true, "CoffeeShop", "02:11:22:33:44:55", true, networks, []);
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Technique == "T1040" && f.Summary.Contains("weak or unencrypted"));
    }

    [Fact]
    public void EvilTwinConflictingSecurityGeneratesCriticalFinding()
    {
        var networks = new List<WifiNetworkEntry>
        {
            new("CorporateNetwork", "00:11:22:33:44:01", 80, "WPA2-Enterprise", "CCMP", 1, "Infrastructure", false),
            new("CorporateNetwork", "00:11:22:33:44:02", 95, "Open", "None", 6, "Infrastructure", false)
        };

        var findings = WirelessPostureEvaluator.Analyze(true, null, null, true, networks, []);
        Assert.Contains(findings, f => f.Severity == "CRITICAL" && f.Technique == "T1557.002" && f.Summary.Contains("Evil Twin"));
    }

    [Theory]
    [InlineData("Free WiFi Airport")]
    [InlineData("guest-wifi-free")]
    [InlineData("starbucks_wifi")]
    [InlineData("rogue-ap")]
    [InlineData("WiFi Pineapple Nano")]
    [InlineData("flipper-hotspot")]
    public void SuspiciousSsidPatternsGenerateHighFinding(string ssid)
    {
        var networks = new List<WifiNetworkEntry>
        {
            new(ssid, "00:AA:BB:CC:DD:EE", 60, "WPA2-Personal", "CCMP", 11, "Infrastructure", false)
        };

        var findings = WirelessPostureEvaluator.Analyze(true, null, null, true, networks, []);
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Technique == "T1557.002" && f.Summary.Contains("Suspicious or spoofed SSID"));
    }

    [Theory]
    [InlineData("00:13:37:AA:BB:CC", "Hak5 WiFi Pineapple")]
    [InlineData("AA:BB:CC:11:22:33", "Common spoofed OUI")]
    [InlineData("00:11:22:44:55:66", "Common spoofed OUI")]
    [InlineData("DE:AD:BE:77:88:99", "Common spoofed OUI pattern")]
    public void AttackToolOuisGenerateCriticalFinding(string bssid, string toolDesc)
    {
        var networks = new List<WifiNetworkEntry>
        {
            new("NormalName", bssid, 55, "WPA2-Personal", "CCMP", 6, "Infrastructure", false)
        };

        var findings = WirelessPostureEvaluator.Analyze(true, null, null, true, networks, []);
        Assert.Contains(findings, f => f.Severity == "CRITICAL" && f.Technique == "T1200" && f.Summary.Contains(toolDesc));
    }

    [Theory]
    [InlineData("Flipper Zero BLE")]
    [InlineData("Ubertooth One")]
    [InlineData("BlueHydra Pro")]
    [InlineData("BT Keylogger HID")]
    [InlineData("WiFi Pineapple Portal")]
    public void SuspiciousBluetoothNamesGenerateHighFinding(string btName)
    {
        var btDevices = new List<BluetoothDeviceEntry>
        {
            new("00:11:22:33:44:55", btName, "HKLM\\...\\Devices\\001122334455", true)
        };

        var findings = WirelessPostureEvaluator.Analyze(true, null, null, true, [], btDevices);
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Technique == "T1011.001" && f.Summary.Contains("Suspicious Bluetooth device name"));
    }

    [Fact]
    public void ClientValidatesWirelessSnapshotSchemaAndBounds()
    {
        var valid = new WirelessSnapshot(
            SchemaVersion: 1,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            WifiAdapterAvailable: true,
            ConnectedSsid: "Home",
            ConnectedBssid: "00:11:22:33:44:55",
            BluetoothAdapterEnabled: true,
            WifiNetworks: [],
            BluetoothDevices: [],
            Findings: [],
            Warnings: []);

        Assert.True(WirelessInventoryClient.IsValid(valid));
        Assert.False(WirelessInventoryClient.IsValid(null));
        Assert.False(WirelessInventoryClient.IsValid(valid with { SchemaVersion = 2 }));
    }

    [Fact]
    public void WirelessInventoryProviderCapturesValidLocalSnapshot()
    {
        var provider = new WirelessInventoryProvider();
        var snapshot = provider.Capture();

        Assert.NotNull(snapshot);
        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.NotNull(snapshot.WifiNetworks);
        Assert.NotNull(snapshot.BluetoothDevices);
        Assert.NotNull(snapshot.Findings);
        Assert.NotNull(snapshot.Warnings);
        Assert.True(WirelessInventoryClient.IsValid(snapshot));
    }
}
