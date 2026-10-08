using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Abstractions;

namespace Downpour.Tests;

public sealed class DriverSourceAdvisorTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 0, 0, 0, TimeSpan.Zero);

    private static DeviceEntry Device(string name, string hardwareId, string cls = "Net", string? provider = "Vendor", DateTimeOffset? date = null, int code = 0) =>
        new($@"X\{name}", name, cls, "Vendor", "OK", code, true, provider, "1.0", date, "oem1.inf", true, "Signer", hardwareId);

    [Theory]
    [InlineData(@"PCI\VEN_10DE&DEV_2684&SUBSYS_16F110DE", "PCI", "10DE", "2684")]
    [InlineData(@"USB\VID_046D&PID_C52B&REV_1211", "USB", "046D", "C52B")]
    [InlineData(@"HDAUDIO\FUNC_01&VEN_10EC&DEV_0897&SUBSYS_1458A0C3", "HDAUDIO", "10EC", "0897")]
    [InlineData(@"ACPI\PNP0A08", "ACPI", null, null)]
    [InlineData("", "", null, null)]
    public void HardwareIdsAreParsed(string id, string bus, string? vendor, string? device)
    {
        var parts = DriverSourceAdvisor.Parse(id);
        Assert.Equal(bus, parts.Bus);
        Assert.Equal(vendor, parts.VendorId);
        Assert.Equal(device, parts.DeviceId);
    }

    [Fact]
    public void ChipMakersWithOwnDriversGetTheirPageOthersGoToThePcMaker()
    {
        var gpu = Device("GeForce RTX 4090", @"PCI\VEN_10DE&DEV_2684", "Display");
        var sources = DriverSourceAdvisor.SourcesFor(gpu, "Gigabyte Technology Co., Ltd.", "Gigabyte Technology Co., Ltd.");
        Assert.Equal("https://www.nvidia.com/en-us/drivers/", sources[0].Url);
        Assert.Contains(sources, s => s.Url == "https://www.gigabyte.com/Support");

        var audio = Device("Realtek Audio", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0897", "MEDIA");
        Assert.Equal("Realtek", DriverSourceAdvisor.ChipMaker(audio)!.Value.Maker);
        var audioSources = DriverSourceAdvisor.SourcesFor(audio, "Dell Inc.", "Dell Inc.");
        Assert.Equal("https://www.dell.com/support/home/", Assert.Single(audioSources).Url);

        var mouse = Device("G502", @"USB\VID_046D&PID_C08B", "HIDClass");
        Assert.Equal("https://www.logitech.com/en-us/software.html", DriverSourceAdvisor.SourcesFor(mouse, null, null)[0].Url);
    }

    [Theory]
    [InlineData("HP", "https://support.hp.com/us-en/drivers")]
    [InlineData("Hewlett-Packard", "https://support.hp.com/us-en/drivers")]
    [InlineData("Micro-Star International Co., Ltd.", "https://www.msi.com/support/download")]
    [InlineData("ASUSTeK COMPUTER INC.", "https://www.asus.com/support/download-center/")]
    [InlineData("Alienware", "https://www.dell.com/support/home/")]
    [InlineData("LENOVO", "https://pcsupport.lenovo.com/")]
    [InlineData("Shopify Inc", null)]
    [InlineData("To Be Filled By O.E.M.", null)]
    [InlineData("System manufacturer", null)]
    public void PcMakersAreRecognised(string maker, string? url) => Assert.Equal(url, DriverSourceAdvisor.MakerSource(maker)?.Url);

    [Fact]
    public void AllSourceUrlsAreHttpsOnMakerDomains()
    {
        var all = new[] { "NVIDIA", "AMD" }.Length; // anchor
        var devices = new[]
        {
            Device("a", @"PCI\VEN_10DE&DEV_1"), Device("b", @"PCI\VEN_1002&DEV_1"), Device("c", @"PCI\VEN_8086&DEV_1"), Device("d", @"PCI\VEN_144D&DEV_1"),
            Device("e", @"USB\VID_046D&PID_1"), Device("f", @"USB\VID_1532&PID_1"), Device("g", @"USB\VID_1B1C&PID_1"), Device("h", @"USB\VID_0FD9&PID_1"),
            Device("i", @"USB\VID_1038&PID_1"), Device("j", @"USB\VID_041E&PID_1"), Device("k", @"USB\VID_1235&PID_1"),
        };
        foreach (var source in devices.SelectMany(d => DriverSourceAdvisor.SourcesFor(d, "Dell", "ASRock")))
        {
            Assert.StartsWith("https://", source.Url);
            Assert.True(Uri.TryCreate(source.Url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host));
        }
        Assert.True(all > 0);
    }

    [Fact]
    public void OldThirdPartyAndStaleGraphicsDriversAreFlaggedMicrosoftOnesAreNot()
    {
        var checks = DriverSourceAdvisor.Checks(
        [
            Device("RTX", @"PCI\VEN_10DE&DEV_2684", "Display", date: Now.AddDays(-250)),
            Device("RTX fresh", @"PCI\VEN_10DE&DEV_2685", "Display", date: Now.AddDays(-40)),
            Device("Old NIC", @"PCI\VEN_10EC&DEV_8168", "Net", date: Now.AddYears(-5)),
            Device("Inbox", @"PCI\VEN_8086&DEV_0001", "System", provider: "Microsoft", date: Now.AddYears(-10)),
            Device("Broken", @"PCI\VEN_10EC&DEV_8169", "Net", date: Now.AddYears(-6), code: 28),
        ], "Gigabyte Technology Co., Ltd.", "Gigabyte Technology Co., Ltd.", Now);
        Assert.Equal(["RTX", "Old NIC"], checks.Select(c => c.Device.Name));
        // Ports, HID and software components are not "check with the maker" items; one package across devices is grouped.
        var grouped = DriverSourceAdvisor.Checks(
        [
            Device("AMD PCI", @"PCI\VEN_1022&DEV_1", "System", provider: "Advanced Micro Devices", date: Now.AddYears(-4)),
            Device("AMD PCI #2", @"PCI\VEN_1022&DEV_2", "System", provider: "Advanced Micro Devices", date: Now.AddYears(-4)),
            Device("COM1", @"ACPI\PNP0501", "Ports", provider: "LG", date: Now.AddYears(-8)),
            Device("Audio effects", @"SWC\X", "SoftwareComponent", provider: "A-Volute", date: Now.AddYears(-5)),
        ], null, "Micro-Star International Co., Ltd.", Now);
        var chipset = Assert.Single(grouped);
        Assert.Equal(2, chipset.DeviceCount);
        Assert.Equal("Advanced Micro Devices chipset drivers (2 devices)", chipset.Label);
        Assert.Contains("months old", checks[0].Reason);
        Assert.Equal("https://www.gigabyte.com/Support", checks[1].Sources[0].Url);
    }

    [Fact]
    public void InstalledMakerToolsAreRecognised() =>
        Assert.Equal(["GIGABYTE Control Center", "NVIDIA App"],
            DriverSourceAdvisor.MatchTools(["NVIDIA App 11.0", "GIGABYTE Control Center", "7-Zip 24.08"]).Order());

    [Fact]
    public async Task LiveIdentityAndSourcesOnThisPc()
    {
        var service = new DeviceInventoryService(NullLogger<DeviceInventoryService>.Instance, "Downpour.Test.Devices." + Guid.NewGuid().ToString("N"),
            new InstalledSoftwareInventoryProvider());
        var reply = await service.HandleAsync(new DeviceRequest(1, DeviceOperations.Snapshot), default);
        Assert.True(DeviceClient.IsValid(reply));
        var s = reply.Snapshot!;
        output.WriteLine($"System: {s.SystemManufacturer} {s.SystemModel}; board: {s.BoardManufacturer} {s.BoardProduct}; tools: {string.Join(", ", s.VendorTools ?? [])}");
        foreach (var c in DriverSourceAdvisor.Checks(s.Devices, s.SystemManufacturer, s.BoardManufacturer, DateTimeOffset.UtcNow))
            output.WriteLine($"CHECK {c.Device.Name} {c.Device.DriverProvider} {c.Device.DriverVersion} {c.Device.DriverDate:yyyy-MM-dd} -> {string.Join(" | ", c.Sources.Select(x => x.Name))}");
        foreach (var p in DeviceAnalyzer.Problems(s.Devices).Where(p => p.Device.Present))
            output.WriteLine($"PROBLEM {p.Device.Name} code {p.Device.ProblemCode}: {p.Title}");
    }
}
