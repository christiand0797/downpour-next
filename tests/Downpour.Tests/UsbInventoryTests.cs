using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class UsbInventoryTests
{
    [Fact]
    public void CleanUsbSnapshotProducesNoFindings()
    {
        var devices = new List<UsbConnectedDevice>
        {
            new("E:", "FlashDrive", "FAT32", 1024 * 1024 * 1024, 512 * 1024 * 1024, "SanDisk", "Ultra", "123456", false, false, "Removable")
        };
        var history = new List<UsbDeviceHistoryEntry>
        {
            new("USB\\VID_0781&PID_5581\\123456", "SanDisk", "Ultra", "1.0", "123456", "SanDisk Ultra USB Device", "USB\\VID_0781&PID_5581")
        };

        var findings = UsbPostureEvaluator.Analyze(true, devices, history);
        Assert.Empty(findings);
    }

    [Fact]
    public void AutorunFileGeneratesHighFinding()
    {
        var devices = new List<UsbConnectedDevice>
        {
            new("F:", "MaliciousDrive", "NTFS", 2048, 1024, "Vendor", "Product", "SN1", true, false, "Removable")
        };

        var findings = UsbPostureEvaluator.Analyze(true, devices, []);
        Assert.Single(findings);
        var f = findings[0];
        Assert.Equal("HIGH", f.Severity);
        Assert.Equal("T1091", f.Technique);
        Assert.Contains("Autorun file detected", f.Summary);
        Assert.Equal("F::autorun", f.Indicator);
    }

    [Fact]
    public void SuspiciousRootFileGeneratesMediumFinding()
    {
        var devices = new List<UsbConnectedDevice>
        {
            new("G:", "PayloadDrive", "FAT32", 4096, 2048, "Vendor", "Product", "SN2", false, true, "Removable")
        };

        var findings = UsbPostureEvaluator.Analyze(true, devices, []);
        Assert.Single(findings);
        var f = findings[0];
        Assert.Equal("MEDIUM", f.Severity);
        Assert.Equal("T1091", f.Technique);
        Assert.Contains("Suspicious standalone executable or script", f.Summary);
    }

    [Theory]
    [InlineData("Rubber Ducky", "rubber ducky")]
    [InlineData("BadUSB Device", "badusb")]
    [InlineData("Flipper Zero", "flipper")]
    [InlineData("Teensy USB Keystroke Injector", "teensy")]
    [InlineData("Maltronics KeyGrabber", "maltronics")]
    [InlineData("Hak5 Bash Bunny", "bash bunny")]
    [InlineData("O.MG Cable v2", "o.mg")]
    public void BadUsbSignaturesGenerateCriticalFindings(string friendlyName, string expectedPattern)
    {
        var history = new List<UsbDeviceHistoryEntry>
        {
            new("DEV1", "Vendor", "Product", "1.0", "SN999", friendlyName, "USB\\VID_9999&PID_1111")
        };

        var findings = UsbPostureEvaluator.Analyze(true, [], history);
        Assert.Single(findings);
        var f = findings[0];
        Assert.Equal("CRITICAL", f.Severity);
        Assert.Equal("T1200", f.Technique);
        Assert.Contains(expectedPattern, f.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DisabledUsbStorageGeneratesLowFinding()
    {
        var findings = UsbPostureEvaluator.Analyze(false, [], []);
        Assert.Single(findings);
        var f = findings[0];
        Assert.Equal("LOW", f.Severity);
        Assert.Equal("T1200", f.Technique);
        Assert.Equal("USBSTOR:Disabled", f.Indicator);
    }

    [Fact]
    public void ClientValidatesUsbSnapshotSchemaAndBounds()
    {
        var valid = new UsbSnapshot(
            SchemaVersion: 1,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            UsbStorageServiceEnabled: true,
            ConnectedDevices: [],
            History: [],
            Findings: [],
            Warnings: []);

        Assert.True(UsbInventoryClient.IsValid(valid));
        Assert.False(UsbInventoryClient.IsValid(null));
        Assert.False(UsbInventoryClient.IsValid(valid with { SchemaVersion = 2 }));
    }

    [Fact]
    public void ClientRejectsInvalidSeverityInFindings()
    {
        var invalid = new UsbSnapshot(
            SchemaVersion: 1,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            UsbStorageServiceEnabled: true,
            ConnectedDevices: [],
            History: [],
            Findings: [new UsbFinding("INVALID_SEV", "T1091", "Test summary", "test")],
            Warnings: []);

        Assert.False(UsbInventoryClient.IsValid(invalid));
    }

    [Fact]
    public void UsbInventoryProviderCapturesValidLocalSnapshot()
    {
        var provider = new UsbInventoryProvider();
        var snapshot = provider.Capture();

        Assert.NotNull(snapshot);
        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.NotNull(snapshot.ConnectedDevices);
        Assert.NotNull(snapshot.History);
        Assert.NotNull(snapshot.Findings);
        Assert.NotNull(snapshot.Warnings);
        Assert.True(UsbInventoryClient.IsValid(snapshot));
    }
}
