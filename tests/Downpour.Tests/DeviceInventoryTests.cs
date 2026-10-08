using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class DeviceInventoryTests
{
    private static DeviceEntry Device(string name, int code = 0, string? provider = "Contoso", bool present = true, string status = "OK",
        string? inf = "oem1.inf", string? hardwareId = @"PCI\VEN_8086&DEV_1234&SUBSYS_1", DateTimeOffset? date = null) =>
        new($@"PCI\{name}", name, "Net", "Contoso", status, code, present, provider, "1.0", date, inf, true, "Microsoft Windows Hardware Compatibility Publisher", hardwareId);

    [Fact]
    public void HealthyDevicesHaveNoProblem() => Assert.Null(DeviceAnalyzer.Problem(Device("Wi-Fi")));

    [Theory]
    [InlineData(28, true, "MEDIUM", "Driver not installed")]
    [InlineData(43, false, "MEDIUM", "Device reported a problem")]
    [InlineData(52, false, "HIGH", "Signature not verified")]
    [InlineData(22, false, "LOW", "Disabled")]
    [InlineData(777, false, "MEDIUM", "Problem code 777")]
    public void ProblemCodesAreExplainedWithAFix(int code, bool missing, string severity, string title)
    {
        var problem = DeviceAnalyzer.Problem(Device("Adapter", code))!;
        Assert.Equal(missing, problem.MissingDriver);
        Assert.Equal(severity, problem.Severity);
        Assert.Equal(title, problem.Title);
        Assert.False(string.IsNullOrWhiteSpace(problem.Fix));
    }

    [Fact]
    public void UnpluggedDevicesAreNotProblems()
    {
        Assert.Null(DeviceAnalyzer.Problem(Device("Old phone", 45, present: false)));
        Assert.Null(DeviceAnalyzer.Problem(Device("Old phone", 24, present: false)));
    }

    [Fact]
    public void PresentDeviceInErrorWithoutAnyDriverIsMissingADriver()
    {
        var problem = DeviceAnalyzer.Problem(Device("Unknown device", 0, provider: null, status: "Error", inf: null))!;
        Assert.True(problem.MissingDriver);
    }

    [Fact]
    public void ProblemsAreOrderedBySeverityThenMissingDrivers()
    {
        var problems = DeviceAnalyzer.Problems([Device("A", 22), Device("B", 28), Device("C", 52), Device("D")]);
        Assert.Equal(["C", "B", "A"], problems.Select(p => p.Device.Name));
    }

    [Fact]
    public void UpdateOffersMatchDevicesByHardwareIdThenModel()
    {
        var devices = new[] { Device("Intel Wi-Fi 6E AX211"), Device("Realtek Audio", hardwareId: @"HDAUDIO\FUNC_01&VEN_10EC") };
        var byId = new DriverUpdateOffer("Intel - Net - 23.0", "Net", "Something else", "Intel", "Intel", @"PCI\VEN_8086&DEV_1234", null, 1000);
        Assert.Equal("Intel Wi-Fi 6E AX211", Assert.Single(DeviceAnalyzer.Targets(byId, devices)).Name);
        var byModel = new DriverUpdateOffer("Realtek - Audio", "MEDIA", "Realtek Audio", "Realtek", "Realtek", null, null, null);
        Assert.Equal("Realtek Audio", Assert.Single(DeviceAnalyzer.Targets(byModel, devices)).Name);
    }

    [Fact]
    public void DriverAgeAndCimDates()
    {
        Assert.Equal(new DateTimeOffset(2023, 1, 15, 0, 0, 0, TimeSpan.Zero), DeviceInventoryService.CimDate("20230115000000.******+000"));
        Assert.Null(DeviceInventoryService.CimDate("garbage"));
        Assert.Equal(3, DeviceAnalyzer.AgeYears(Device("X", date: new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero)), new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.Null(DeviceAnalyzer.AgeYears(Device("X", date: new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)), DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ClientRejectsMalformedReplies()
    {
        var snapshot = new DeviceInventorySnapshot(1, DateTimeOffset.UtcNow, [Device("Wi-Fi")], [], UpdateSearchStates.NotSearched, null, null, []);
        Assert.True(DeviceClient.IsValid(new DeviceResponse(1, true, "snapshot", snapshot)));
        Assert.False(DeviceClient.IsValid(new DeviceResponse(1, true, "snapshot", snapshot with { Devices = [Device("bad\u0007")] })));
        Assert.False(DeviceClient.IsValid(new DeviceResponse(1, true, "snapshot", snapshot with { Devices = [Device("x", code: -1)] })));
        Assert.False(DeviceClient.IsValid(new DeviceResponse(2, true, "snapshot", snapshot)));
    }

    [Fact]
    public async Task LiveInventoryOnThisPcReturnsDevicesWithDrivers()
    {
        var devices = DeviceInventoryService.ReadDevices();
        Assert.True(devices.Count > 20, $"only {devices.Count} devices");
        Assert.Contains(devices, d => d.DriverProvider is not null && d.DriverVersion is not null);
        var service = new DeviceInventoryService(NullLogger<DeviceInventoryService>.Instance, "Downpour.Test.Devices." + Guid.NewGuid().ToString("N"));
        var reply = await service.HandleAsync(new DeviceRequest(1, DeviceOperations.Snapshot), default);
        Assert.True(DeviceClient.IsValid(reply));
        Assert.False((await service.HandleAsync(new DeviceRequest(1, "install"), default)).Accepted);
    }
}
