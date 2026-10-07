using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class IoTDeviceScannerTests
{
    [Theory]
    [InlineData("C4:DD:57:11:22:33", "Espressif Systems (ESP8266/32)")]
    [InlineData("50:02:91:AA:BB:CC", "Tuya Smart (smart plug/bulb/thermostat)")]
    [InlineData("E4:24:6C:01:02:03", "Hikvision IP Camera")]
    [InlineData("50:C7:BF:44:55:66", "TP-Link (router/smart plug)")]
    [InlineData("B8:27:EB:77:88:99", "Raspberry Pi Foundation")]
    [InlineData("F8:FF:C2:12:34:56", "Apple (iPhone/iPad/Mac)")]
    [InlineData("f0:81:73:99:88:77", "Ring / Amazon (doorbell/camera)")]
    public void ResolveVendor_IdentifiesKnownOuiPrefixes(string mac, string expectedVendor)
    {
        var vendor = IoTDeviceScanner.ResolveVendor(mac);
        Assert.Equal(expectedVendor, vendor);
    }

    [Fact]
    public void ResolveVendor_HandlesUnknownOrInvalidMac()
    {
        Assert.Equal("Unknown Manufacturer", IoTDeviceScanner.ResolveVendor("02:00:00:11:22:33"));
        Assert.Equal("Unknown Device", IoTDeviceScanner.ResolveVendor(""));
        Assert.Equal("Unknown Device", IoTDeviceScanner.ResolveVendor("12:34"));
    }

    [Fact]
    public void CategorizeDevice_ClassifiesCorrectly()
    {
        var camera = IoTDeviceScanner.CategorizeDevice("Hikvision IP Camera", [554]);
        Assert.Equal("IP Camera / Surveillance", camera);

        var smartHome = IoTDeviceScanner.CategorizeDevice("Tuya Smart (smart plug/bulb)", [1883]);
        Assert.Equal("Smart Home / IoT Controller", smartHome);

        var router = IoTDeviceScanner.CategorizeDevice("TP-Link Router", [80, 443]);
        Assert.Equal("Router / Network Infrastructure", router);

        var sbc = IoTDeviceScanner.CategorizeDevice("Raspberry Pi 4", []);
        Assert.Equal("Embedded Single-Board Computer", sbc);

        var mobile = IoTDeviceScanner.CategorizeDevice("Apple (iPhone/iPad)", []);
        Assert.Equal("Mobile / Smart Device", mobile);
    }

    [Fact]
    public void GenerateReport_FormatsSubnetSummaryAndDevices()
    {
        var dev1 = new IoTDevice(
            IpAddress: "192.168.1.100",
            MacAddress: "C4:DD:57:AB:CD:EF",
            HostName: "esp-device.local",
            Vendor: "Espressif Systems (ESP8266/32)",
            DeviceCategory: "Smart Home / IoT Controller",
            OpenPorts: [80, 9999],
            IdentifiedServices: ["HTTP web admin interface"],
            BotnetIndicators: ["Mozi botnet DHT C2 active"],
            ThreatLevel: "CRITICAL",
            RiskScore: 75,
            IsSuspicious: true,
            DiscoveredAtUtc: DateTimeOffset.UtcNow);

        var summary = new IoTSummary(
            TotalDevices: 1,
            HighRiskDevices: 1,
            BotnetThreats: 1,
            SmartHomeDevices: 1,
            Cameras: 0,
            ScanCompletedAtUtc: DateTimeOffset.UtcNow,
            ScanFindings: ["ALERT: Detected 1 device(s) exhibiting botnet indicators."]);

        var snapshot = new IoTSnapshot(DateTimeOffset.UtcNow, summary, [dev1]);
        var report = IoTDeviceScanner.GenerateReport(snapshot);

        Assert.Contains("# Downpour IoT Subnet Security Audit Report", report);
        Assert.Contains("**Total Devices Discovered**: 1", report);
        Assert.Contains("**Botnet Threats Detected**: 1", report);
        Assert.Contains("192.168.1.100", report);
        Assert.Contains("Espressif Systems (ESP8266/32)", report);
        Assert.Contains("CRITICAL", report);
        Assert.Contains("Mozi botnet DHT C2 active", report);
    }

    [Fact]
    public void ScanLocalNetwork_ReturnsValidSnapshot()
    {
        var scanner = new IoTDeviceScanner();
        var snapshot = scanner.ScanLocalNetwork();

        Assert.NotNull(snapshot);
        Assert.NotNull(snapshot.Summary);
        Assert.NotNull(snapshot.Devices);
        Assert.True(snapshot.Summary.TotalDevices >= 0);
    }
}
