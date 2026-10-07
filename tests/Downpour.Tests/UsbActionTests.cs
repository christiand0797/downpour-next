using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Xunit;

namespace Downpour.Tests;

public sealed class UsbActionTests : IDisposable
{
    private readonly string _testStateDir;
    private readonly string _auditLogPath;
    private readonly string _blockedStorePath;
    private readonly ActionAuditLog _auditLog;
    private readonly ActionConsentStore _consentStore;
    private readonly SensorSettingsStore _settingsStore;
    private readonly InMemoryUsbDeviceBackend _backend;
    private readonly UsbActionExecutor _executor;
    private readonly UsbActionHandler _handler;

    public UsbActionTests()
    {
        _testStateDir = Path.Combine(Path.GetTempPath(), "downpour_test_usbaction_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testStateDir);
        _auditLogPath = Path.Combine(_testStateDir, "test-audit.v1.jsonl");
        _blockedStorePath = Path.Combine(_testStateDir, "blocked-usb-devices.v1.json");
        _auditLog = new ActionAuditLog(_auditLogPath);
        _consentStore = new ActionConsentStore();

        var settingsPath = Path.Combine(_testStateDir, "sensor-settings.v1.json");
        _settingsStore = new SensorSettingsStore(settingsPath);

        _backend = new InMemoryUsbDeviceBackend();
        _executor = new UsbActionExecutor(_backend, _blockedStorePath);
        _handler = new UsbActionHandler(_executor, _settingsStore, _consentStore, _auditLog);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testStateDir))
                Directory.Delete(_testStateDir, recursive: true);
        }
        catch { }
    }

    [Theory]
    [InlineData("USB\\ROOT_HUB30\\4&1a2b3c", null, false)] // Root Hub
    [InlineData("USB#ROOT_HUB#4&998877", null, false)] // Root Hub variant
    [InlineData("USB\\VID_046D&PID_C52B\\5&112233", "Logitech USB Optical Mouse", false)] // Mouse by name
    [InlineData("HID\\VID_046D&PID_C31C&MI_00\\7&8899", "Standard Keyboard", false)] // Keyboard HID
    [InlineData("USB\\VID_04F3&PID_2345&Col01\\6&55", "Touchpad Sensor", false)] // Touchpad collection
    [InlineData("PCI\\VEN_8086&DEV_A12F\\3&11583659&0&A0", null, false)] // PCI Host Controller
    [InlineData("ACPI\\PNP0A08\\0", null, false)] // ACPI root
    [InlineData("SCSI\\Disk&Ven_NVMe&Prod_SAMSUNG\\4&55", null, false)] // Internal NVMe disk
    [InlineData("IDE\\DiskWDC_WD10EZEX\\5&66", null, false)] // Internal IDE disk
    [InlineData("STORAGE\\Volume\\{12345678-1234}", null, false)] // Storage volume
    [InlineData("SWD\\WPDBUSENUM\\_??_USBSTOR#Disk", null, false)] // Software device bus
    [InlineData("", null, false)] // Empty
    [InlineData("   ", null, false)] // Whitespace
    [InlineData("AB", null, false)] // Too short
    [InlineData("Disk&Ven_SanDisk&Prod_Cruzer\\123\n45", null, false)] // Newline
    [InlineData("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\0123456789ABCDEF", "SanDisk Cruzer", true)] // External USB flash drive
    [InlineData("USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler\\0011223344", "Kingston DataTraveler", true)] // USBSTOR instance
    [InlineData("USB\\VID_0781&PID_5581\\AA010502201", "SanDisk Ultra USB 3.0", true)] // USB device instance
    public void ValidateDevice_EnforcesImmutableDenyList(string deviceId, string? friendlyName, bool shouldBeAllowed)
    {
        var (allowed, denyReason) = _executor.ValidateDevice(deviceId, friendlyName);
        if (shouldBeAllowed)
        {
            Assert.True(allowed);
            Assert.Null(denyReason);
        }
        else
        {
            Assert.False(allowed);
            Assert.NotNull(denyReason);
        }
    }

    [Fact]
    public void ActionCatalog_ContainsUsbActionsAndSwitches()
    {
        var catalog = DefaultActionCatalog.GetCatalog();
        Assert.True(catalog.Actions.ContainsKey(ActionKinds.BlockUsbDevice));
        Assert.True(catalog.Actions.ContainsKey(ActionKinds.UnblockUsbDevice));
        Assert.True(catalog.Actions.ContainsKey(ActionKinds.SetUsbStorage));

        var switches = DefaultActionCatalog.GetDefaultFeatureSwitches();
        Assert.True(switches.ContainsKey(ActionKinds.BlockUsbDevice));
        Assert.False(switches[ActionKinds.BlockUsbDevice].Enabled);
        Assert.True(switches.ContainsKey(ActionKinds.UnblockUsbDevice));
        Assert.False(switches[ActionKinds.UnblockUsbDevice].Enabled);
        Assert.True(switches.ContainsKey(ActionKinds.SetUsbStorage));
        Assert.False(switches[ActionKinds.SetUsbStorage].Enabled);
    }

    [Fact]
    public void ActionPolicyValidator_GeneratesUsbActionPreviews()
    {
        var catalog = DefaultActionCatalog.GetCatalog();
        var switches = DefaultActionCatalog.GetDefaultFeatureSwitches();
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(switches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.BlockUsbDevice] = switches[ActionKinds.BlockUsbDevice] with { Enabled = true },
            [ActionKinds.UnblockUsbDevice] = switches[ActionKinds.UnblockUsbDevice] with { Enabled = true },
            [ActionKinds.SetUsbStorage] = switches[ActionKinds.SetUsbStorage] with { Enabled = true }
        };
        var validator = new ActionPolicyValidator(catalog, enabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);

        var objId1 = "obj-" + Guid.NewGuid().ToString("N");
        var blockRequest = new ActionRequest(
            1, Guid.NewGuid(), ActionKinds.BlockUsbDevice, objId1, "1.0.0",
            true, "S-1-5-21-123", DateTimeOffset.UtcNow,
            new Dictionary<string, string> { ["deviceId"] = "Disk&Ven_SanDisk&Prod_Cruzer\\12345" });

        var blockPreview = validator.GeneratePreview(blockRequest);
        Assert.Equal(ActionKinds.BlockUsbDevice, blockPreview.ActionKind);
        Assert.NotEmpty(blockPreview.ExpectedEffects);
        Assert.NotEmpty(blockPreview.Risks);
        Assert.NotEmpty(blockPreview.RollbackSteps);

        var objId2 = "obj-" + Guid.NewGuid().ToString("N");
        var unblockRequest = new ActionRequest(
            1, Guid.NewGuid(), ActionKinds.UnblockUsbDevice, objId2, "1.0.0",
            true, "S-1-5-21-123", DateTimeOffset.UtcNow,
            new Dictionary<string, string> { ["deviceId"] = "Disk&Ven_SanDisk&Prod_Cruzer\\12345" });

        var unblockPreview = validator.GeneratePreview(unblockRequest);
        Assert.Equal(ActionKinds.UnblockUsbDevice, unblockPreview.ActionKind);
        Assert.NotEmpty(unblockPreview.ExpectedEffects);

        var objId3 = "obj-" + Guid.NewGuid().ToString("N");
        var storageRequest = new ActionRequest(
            1, Guid.NewGuid(), ActionKinds.SetUsbStorage, objId3, "1.0.0",
            true, "S-1-5-21-123", DateTimeOffset.UtcNow,
            new Dictionary<string, string> { ["enabled"] = "false" });

        var storagePreview = validator.GeneratePreview(storageRequest);
        Assert.Equal(ActionKinds.SetUsbStorage, storagePreview.ActionKind);
        Assert.NotEmpty(storagePreview.ExpectedEffects);
    }

    [Fact]
    public async Task Handler_RejectsUnauthorizedCaller()
    {
        var request = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewBlockDevice,
            DeviceId: "Disk&Ven_SanDisk\\12345");

        var response = await _handler.HandleAsync(request, "Caller is not authorized.", CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("denied-caller", response.ResultCode);
        Assert.Contains("not authorized", response.Message);
    }

    [Fact]
    public async Task Handler_RejectsWhenFeatureDisabledInSettings()
    {
        _settingsStore.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.UsbActions, false));

        var request = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewBlockDevice,
            DeviceId: "Disk&Ven_SanDisk\\12345");

        var response = await _handler.HandleAsync(request, null, CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("disabled", response.ResultCode);
        Assert.Contains("turned off in Settings", response.Message);
    }

    [Fact]
    public async Task Handler_PreviewBlockDevice_MintsConsentTokenForValidDevice()
    {
        var devId = "Disk&Ven_SanDisk&Prod_Cruzer\\998877";
        _backend.AddDevice(devId);

        var request = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewBlockDevice,
            DeviceId: devId,
            FriendlyName: "SanDisk Flash Drive");

        var response = await _handler.HandleAsync(request, null, CancellationToken.None);

        Assert.True(response.Accepted);
        Assert.Equal("preview-generated", response.ResultCode);
        Assert.NotNull(response.Preview);
        Assert.NotNull(response.Preview.ConsentToken);
        Assert.NotEmpty(response.Preview.ExpectedEffects);
        Assert.NotEmpty(response.Preview.Risks);
    }

    [Fact]
    public async Task Handler_PreviewBlockDevice_DeniesProtectedKeyboardOrMouse()
    {
        var devId = "USB\\VID_046D&PID_C52B\\1122";

        var request = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewBlockDevice,
            DeviceId: devId,
            FriendlyName: "Wireless Keyboard Receiver");

        var response = await _handler.HandleAsync(request, null, CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("denied-protected-device", response.ResultCode);
        Assert.NotNull(response.Preview);
        Assert.NotNull(response.Preview.DenyReason);
        Assert.Null(response.Preview.ConsentToken);
    }

    [Fact]
    public async Task Handler_BlockDevice_RequiresValidConsentToken()
    {
        var devId = "Disk&Ven_SanDisk&Prod_Cruzer\\112233";
        _backend.AddDevice(devId);

        var request = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.BlockDevice,
            DeviceId: devId,
            ConsentToken: "invalid-or-fake-token");

        var response = await _handler.HandleAsync(request, null, CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("denied-consent", response.ResultCode);
    }

    [Fact]
    public async Task Handler_FullBlockAndUnblockCycle_WorksAndAudits()
    {
        var devId = "Disk&Ven_SanDisk&Prod_Cruzer\\445566";
        _backend.AddDevice(devId);

        // 1. Preview block
        var previewReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewBlockDevice,
            DeviceId: devId,
            FriendlyName: "Operator USB Drive");
        var previewResp = await _handler.HandleAsync(previewReq, null, CancellationToken.None);
        Assert.True(previewResp.Accepted);
        var consentToken = previewResp.Preview!.ConsentToken!;

        // 2. Block device
        var blockReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.BlockDevice,
            DeviceId: devId,
            FriendlyName: "Operator USB Drive",
            ConsentToken: consentToken);
        var blockResp = await _handler.HandleAsync(blockReq, null, CancellationToken.None);
        Assert.True(blockResp.Accepted);
        Assert.Equal("blocked", blockResp.ResultCode);
        Assert.True(_backend.IsDeviceDisabled(devId));
        Assert.True(_executor.IsDeviceBlocked(devId));

        // 3. Preview unblock
        var unblockPrevReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewUnblockDevice,
            DeviceId: devId);
        var unblockPrevResp = await _handler.HandleAsync(unblockPrevReq, null, CancellationToken.None);
        Assert.True(unblockPrevResp.Accepted);
        var unblockToken = unblockPrevResp.Preview!.ConsentToken!;

        // 4. Unblock device
        var unblockReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.UnblockDevice,
            DeviceId: devId,
            ConsentToken: unblockToken);
        var unblockResp = await _handler.HandleAsync(unblockReq, null, CancellationToken.None);
        Assert.True(unblockResp.Accepted);
        Assert.Equal("unblocked", unblockResp.ResultCode);
        Assert.False(_backend.IsDeviceDisabled(devId));
        Assert.False(_executor.IsDeviceBlocked(devId));

        // Verify audit log has entries
        var auditLines = _auditLog.ReadRecent(10);
        Assert.True(auditLines.Count >= 4);
        Assert.Contains(auditLines, l => l.Contains(UsbActionOperations.BlockDevice) && l.Contains("blocked"));
        Assert.Contains(auditLines, l => l.Contains(UsbActionOperations.UnblockDevice) && l.Contains("unblocked"));
    }

    [Fact]
    public async Task Handler_UsbStorageToggle_WorksWithConsent()
    {
        Assert.True(_backend.GetUsbStorageEnabled());

        // 1. Preview disable
        var prevReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewSetUsbStorage,
            UsbStorageEnabled: false);
        var prevResp = await _handler.HandleAsync(prevReq, null, CancellationToken.None);
        Assert.True(prevResp.Accepted);
        var token = prevResp.Preview!.ConsentToken!;

        // 2. Execute disable
        var setReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.SetUsbStorage,
            UsbStorageEnabled: false,
            ConsentToken: token);
        var setResp = await _handler.HandleAsync(setReq, null, CancellationToken.None);
        Assert.True(setResp.Accepted);
        Assert.Equal("updated", setResp.ResultCode);
        Assert.False(_backend.GetUsbStorageEnabled());

        // 3. Preview enable
        var prevEnableReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.PreviewSetUsbStorage,
            UsbStorageEnabled: true);
        var prevEnableResp = await _handler.HandleAsync(prevEnableReq, null, CancellationToken.None);
        Assert.True(prevEnableResp.Accepted);
        var enableToken = prevEnableResp.Preview!.ConsentToken!;

        // 4. Execute enable
        var setEnableReq = new UsbActionRequest(
            1, Guid.NewGuid(), UsbActionOperations.SetUsbStorage,
            UsbStorageEnabled: true,
            ConsentToken: enableToken);
        var setEnableResp = await _handler.HandleAsync(setEnableReq, null, CancellationToken.None);
        Assert.True(setEnableResp.Accepted);
        Assert.Equal("updated", setEnableResp.ResultCode);
        Assert.True(_backend.GetUsbStorageEnabled());
    }

    [Fact]
    public void ParseStrictRequest_ValidatesRequestBounds()
    {
        var validJson = """
            {
              "schemaVersion": 1,
              "requestId": "11111111-2222-3333-4444-555555555555",
              "operation": "preview-block-device",
              "deviceId": "Disk&Ven_SanDisk\\12345",
              "friendlyName": "Flash Drive",
              "usbStorageEnabled": true
            }
            """u8.ToArray();

        var parsed = UsbActionPipeWorker.ParseStrictRequest(validJson);
        Assert.NotNull(parsed);
        Assert.Equal(1, parsed.SchemaVersion);
        Assert.Equal(Guid.Parse("11111111-2222-3333-4444-555555555555"), parsed.RequestId);
        Assert.Equal(UsbActionOperations.PreviewBlockDevice, parsed.Operation);
        Assert.Equal("Disk&Ven_SanDisk\\12345", parsed.DeviceId);

        // Unknown extra property rejected
        var invalidJson = """
            {
              "schemaVersion": 1,
              "requestId": "11111111-2222-3333-4444-555555555555",
              "operation": "preview-block-device",
              "extraProperty": "injection"
            }
            """u8.ToArray();

        Assert.Null(UsbActionPipeWorker.ParseStrictRequest(invalidJson));

        // Schema version mismatch rejected
        var wrongSchema = """
            {
              "schemaVersion": 2,
              "requestId": "11111111-2222-3333-4444-555555555555",
              "operation": "preview-block-device"
            }
            """u8.ToArray();

        Assert.Null(UsbActionPipeWorker.ParseStrictRequest(wrongSchema));
    }
}
