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
    public void UpdateOffersMatchExactHardwareAndCompatibleIdsWithProvenance()
    {
        var devices = new[]
        {
            Device("Intel Wi-Fi 6E AX211") with { HardwareIds = [@"PCI\VEN_8086&DEV_1234&SUBSYS_1", @"PCI\VEN_8086&DEV_1234"] },
            Device("Realtek Audio", hardwareId: @"HDAUDIO\FUNC_01&VEN_10EC") with { CompatibleIds = [@"HDAUDIO\FUNC_01"] }
        };
        var byId = new DriverUpdateOffer("Intel - Net - 23.0", "Net", "Something else", "Intel", "Intel", @"PCI\VEN_8086&DEV_1234", null, 1000);
        Assert.Equal("Intel Wi-Fi 6E AX211", Assert.Single(DeviceAnalyzer.Targets(byId, devices)).Name);
        Assert.Equal("hardware", Assert.Single(DeviceAnalyzer.Matches(byId, devices)).Kind);
        var compatible = byId with { DriverHardwareId = @"hdaudio\func_01" };
        var match = Assert.Single(DeviceAnalyzer.Matches(compatible, devices));
        Assert.Equal("Realtek Audio", match.Device.Name);
        Assert.Equal("compatible", match.Kind);
        Assert.Contains(@"hdaudio\func_01", match.Explanation);
    }

    [Fact]
    public void PrefixesAndMatchingNamesNeverEstablishCompatibility()
    {
        var device = Device("Shared model");
        var offer = new DriverUpdateOffer("Driver", "Net", device.Name, "Contoso", "Contoso", @"PCI\VEN_8086&DEV_1234", null, null);
        Assert.Empty(DeviceAnalyzer.Targets(offer, [device]));
        Assert.Empty(DeviceAnalyzer.Targets(offer with { DriverHardwareId = null }, [device]));
        Assert.Empty(DeviceAnalyzer.Targets(offer with { DriverHardwareId = @"PCI\VEN_8086&DEV_1234&SUBSYS_10" }, [device]));
        Assert.Single(DeviceAnalyzer.Targets(offer with { DriverHardwareId = device.HardwareId!.ToLowerInvariant() }, [device]));
    }

    [Fact]
    public void IdentifierCollectionRejectsTruncationAndBoundsBothKinds()
    {
        var ids = DeviceInventoryService.Identifiers(["PCI\\A", "pci\\a", "bad\n", new string('x', 257)], ["PCI\\B"]);
        Assert.Equal(["PCI\\A"], ids.Hardware);
        Assert.Equal(["PCI\\B"], ids.Compatible);
        Assert.True(ids.Truncated);
        var many = DeviceInventoryService.Identifiers(Enumerable.Range(0, 40).Select(i => $"ID{i}"), []);
        Assert.Equal(DeviceInventoryLimits.MaximumIdentifiersPerKind, many.Hardware.Count);
        Assert.True(many.Truncated);
        var large = DeviceInventoryService.Identifiers(Enumerable.Range(0, 16).Select(i => $"{i:D3}" + new string('x', 253)), ["COMPATIBLE"]);
        Assert.Equal(DeviceInventoryLimits.MaximumIdentifierCharacters, large.Hardware.Sum(id => id.Length));
        Assert.Empty(large.Compatible);
        Assert.True(large.Truncated);
    }

    [Fact]
    public void ClientRejectsInvalidIdentifierSetsAndSearchStates()
    {
        var snapshot = Snapshot([Device("Adapter")]);
        Assert.True(DeviceClient.IsValid(snapshot)); // legacy first-ID-only data remains compatible
        foreach (var bad in new IReadOnlyList<string>[] { ["bad\n"], [null!], ["X", "x"], [new string('x', 257)], Enumerable.Range(0, 17).Select(i => i.ToString()).ToArray() })
            Assert.False(DeviceClient.IsValid(snapshot with { Devices = [Device("Adapter") with { CompatibleIds = bad }] }));
        Assert.False(DeviceClient.IsValid(snapshot with { Devices = [Device("Adapter") with { HardwareIds = ["different from legacy first ID"] }] }));
        Assert.False(DeviceClient.IsValid(snapshot with { UpdateSearchState = "invented" }));
        Assert.False(DeviceClient.IsValid(snapshot with { UpdateSearchState = UpdateSearchStates.Partial }));
        Assert.False(DeviceClient.IsValid(snapshot with { UpdateSearchState = UpdateSearchStates.Failed }));
        Assert.True(DeviceClient.IsValid(snapshot with { UpdateSearchState = UpdateSearchStates.Partial, UpdateSearchError = "Incomplete search." }));
        var huge = Enumerable.Range(0, 16).Select(i => $"{i:D3}" + new string('x', 253)).ToArray();
        Assert.False(DeviceClient.IsValid(snapshot with { Devices = [Device("Adapter", hardwareId: huge[0]) with { HardwareIds = huge, CompatibleIds = ["EXCESS"] }] }));
    }

    [Theory]
    [InlineData(2, false, 0, UpdateSearchStates.Done)]
    [InlineData(2, false, 200, UpdateSearchStates.Done)]
    [InlineData(2, false, 201, UpdateSearchStates.Partial)]
    [InlineData(2, true, 0, UpdateSearchStates.Partial)]
    [InlineData(3, false, 1, UpdateSearchStates.Partial)]
    [InlineData(4, false, 0, UpdateSearchStates.Failed)]
    [InlineData(5, false, 2, UpdateSearchStates.Failed)]
    [InlineData(0, false, 0, UpdateSearchStates.Failed)]
    [InlineData(1, false, 0, UpdateSearchStates.Failed)]
    public void WindowsUpdateCompletionAndCappedResultsAreHonest(int code, bool warnings, int count, string expected)
    {
        var result = DeviceInventoryService.SearchOutcome(code, warnings, count);
        Assert.Equal(expected, result.State);
        Assert.Equal(expected == UpdateSearchStates.Done, result.Warning is null);
    }

    [Fact]
    public void DevicePayloadBudgetCountsUtf8AndLeavesRoomForOffersAndMetadata()
    {
        var identifiers = Enumerable.Range(0, 16).Select(i => $"{i:D3}" + new string('界', 253)).ToArray();
        var devices = new List<DeviceEntry>();
        var bytes = 2;
        var large = Device("界", hardwareId: identifiers[0]) with { HardwareIds = identifiers };
        while (DeviceInventoryService.TryAddDevice(devices, large, ref bytes)) { }
        Assert.InRange(devices.Count, 1, 1199);
        Assert.True(bytes <= DeviceInventoryLimits.MaximumDevicePayloadBytes);
        var previous = bytes;
        Assert.False(DeviceInventoryService.TryAddDevice(devices, large, ref bytes));
        Assert.Equal(previous, bytes);
        var payload = BoundedJson.Serialize(new DeviceResponse(1, true, "snapshot", Snapshot(devices)));
        Assert.True(payload.Length + DeviceInventoryLimits.MaximumUpdatePayloadBytes + 16 * 1200 < BoundedJson.MaximumPayloadBytes);
        Assert.True(DeviceClient.IsValid(Snapshot(devices)));
    }

    [Fact]
    public void FingerprintChangesWhenDriverMetadataChangesWithoutCountChanges()
    {
        var snapshot = Snapshot([Device("Adapter")]);
        var original = DeviceAnalyzer.ContentFingerprint(snapshot);
        Assert.Equal(original, DeviceAnalyzer.ContentFingerprint(snapshot with { CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(1) }));
        var device = snapshot.Devices[0];
        foreach (var changed in new[] { device with { DriverVersion = "2.0" }, device with { DriverDate = DateTimeOffset.UtcNow }, device with { DriverSigned = false }, device with { DriverSigner = "New signer" }, device with { Present = false } })
            Assert.NotEqual(original, DeviceAnalyzer.ContentFingerprint(snapshot with { Devices = [changed] }));
        Assert.NotEqual(original, DeviceAnalyzer.ContentFingerprint(snapshot with { Warnings = ["Incomplete."] }));
    }

    [Fact]
    public void MissingOrIncompleteInventoryCannotClaimAllDevicesWorking()
    {
        Assert.Equal("Device health is unavailable", DeviceAnalyzer.HealthSummary(Snapshot([])));
        Assert.Contains("incomplete", DeviceAnalyzer.HealthSummary(Snapshot([Device("Adapter")]) with { Warnings = ["Missing metadata."] }));
        Assert.Contains("No major problems reported", DeviceAnalyzer.HealthSummary(Snapshot([Device("Adapter")])));
    }

    private static DeviceInventorySnapshot Snapshot(IReadOnlyList<DeviceEntry> devices) =>
        new(1, DateTimeOffset.UtcNow, devices, [], UpdateSearchStates.NotSearched, null, null, []);

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
