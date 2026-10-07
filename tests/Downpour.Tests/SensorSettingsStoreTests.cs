using System.Text;
using Downpour.Contracts;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class SensorSettingsStoreTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _settingsFile;

    public SensorSettingsStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "DownpourTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _settingsFile = Path.Combine(_tempDir, "sensor-settings.v1.json");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch { }
    }

    [Fact]
    public void LoadsDefaultsWhenFileDoesNotExist()
    {
        var store = new SensorSettingsStore(_settingsFile);
        var current = store.Current;

        Assert.Equal(1, current.SchemaVersion);
        Assert.True(current.ScriptBlockAnalysis);
        Assert.True(current.IntelLookups);
    }

    [Fact]
    public void PersistsAndAppliesScriptBlockSettingChange()
    {
        var store = new SensorSettingsStore(_settingsFile);
        var reqId = Guid.NewGuid();

        var response = store.Apply(new SensorSettingRequest(1, reqId, SensorSettingKeys.ScriptBlockAnalysis, false));

        Assert.True(response.Accepted);
        Assert.Equal("updated", response.ResultCode);
        Assert.NotNull(response.Settings);
        Assert.False(response.Settings.ScriptBlockAnalysis);
        Assert.True(response.Settings.IntelLookups);

        // Recreate store to verify persistence
        var reloadedStore = new SensorSettingsStore(_settingsFile);
        Assert.False(reloadedStore.Current.ScriptBlockAnalysis);
    }

    [Fact]
    public void PersistsAndAppliesIntelLookupsSettingChange()
    {
        var store = new SensorSettingsStore(_settingsFile);
        var reqId = Guid.NewGuid();

        var response = store.Apply(new SensorSettingRequest(1, reqId, SensorSettingKeys.IntelLookups, false));

        Assert.True(response.Accepted);
        Assert.Equal("updated", response.ResultCode);
        Assert.NotNull(response.Settings);
        Assert.False(response.Settings.IntelLookups);
        Assert.True(response.Settings.ScriptBlockAnalysis);
    }

    [Fact]
    public void RejectsInvalidSchemaVersionOrEmptyRequestId()
    {
        var store = new SensorSettingsStore(_settingsFile);

        var badVersion = store.Apply(new SensorSettingRequest(2, Guid.NewGuid(), SensorSettingKeys.ScriptBlockAnalysis, false));
        Assert.False(badVersion.Accepted);
        Assert.Equal("invalid-request", badVersion.ResultCode);

        var emptyGuid = store.Apply(new SensorSettingRequest(1, Guid.Empty, SensorSettingKeys.ScriptBlockAnalysis, false));
        Assert.False(emptyGuid.Accepted);
        Assert.Equal("invalid-request", emptyGuid.ResultCode);
    }

    [Fact]
    public void RejectsUnknownKey()
    {
        var store = new SensorSettingsStore(_settingsFile);
        var response = store.Apply(new SensorSettingRequest(1, Guid.NewGuid(), "malicious_or_unknown_key", false));

        Assert.False(response.Accepted);
        Assert.Equal("invalid-request", response.ResultCode);
    }

    [Fact]
    public void SupportsGetQueryKey()
    {
        var store = new SensorSettingsStore(_settingsFile);
        var reqId = Guid.NewGuid();
        var response = store.Apply(new SensorSettingRequest(1, reqId, SensorSettingKeys.Get, false));

        Assert.True(response.Accepted);
        Assert.Equal("current", response.ResultCode);
        Assert.NotNull(response.Settings);
        Assert.True(response.Settings.ScriptBlockAnalysis);
    }

    [Fact]
    public void InvokesChangedEventOnUpdate()
    {
        var store = new SensorSettingsStore(_settingsFile);
        SensorSettingsSnapshot? notified = null;
        store.Changed += snapshot => notified = snapshot;

        store.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.ScriptBlockAnalysis, false));

        Assert.NotNull(notified);
        Assert.False(notified.ScriptBlockAnalysis);
    }

    [Fact]
    public void ReportsUnchangedWhenApplyingSameValue()
    {
        var store = new SensorSettingsStore(_settingsFile);
        var response1 = store.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.ScriptBlockAnalysis, false));
        Assert.Equal("updated", response1.ResultCode);

        var response2 = store.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.ScriptBlockAnalysis, false));
        Assert.True(response2.Accepted);
        Assert.Equal("unchanged", response2.ResultCode);
    }

    [Fact]
    public void ParseStrictRequestValidatesJsonCorrectly()
    {
        var validJson = "{\"schemaVersion\":1,\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"key\":\"scriptBlockAnalysis\",\"value\":false}";
        var parsed = SensorSettingsPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(validJson));

        Assert.NotNull(parsed);
        Assert.Equal(1, parsed.SchemaVersion);
        Assert.Equal(Guid.Parse("12345678-1234-1234-1234-123456789abc"), parsed.RequestId);
        Assert.Equal("scriptBlockAnalysis", parsed.Key);
        Assert.False(parsed.Value);
    }

    [Fact]
    public void ParseStrictRequestRejectsMalformedOrExtraneousJson()
    {
        // Extra property
        var extraProp = "{\"schemaVersion\":1,\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"key\":\"scriptBlockAnalysis\",\"value\":false,\"extra\":true}";
        Assert.Null(SensorSettingsPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(extraProp)));

        // Duplicate property
        var dupProp = "{\"schemaVersion\":1,\"schemaVersion\":1,\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"key\":\"scriptBlockAnalysis\",\"value\":false}";
        Assert.Null(SensorSettingsPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(dupProp)));

        // Non-boolean value
        var nonBool = "{\"schemaVersion\":1,\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"key\":\"scriptBlockAnalysis\",\"value\":\"false\"}";
        Assert.Null(SensorSettingsPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(nonBool)));

        // Unknown key
        var badKey = "{\"schemaVersion\":1,\"requestId\":\"12345678-1234-1234-1234-123456789abc\",\"key\":\"otherKey\",\"value\":false}";
        Assert.Null(SensorSettingsPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(badKey)));

        // Oversized payload (> 1024 bytes)
        var oversized = new byte[1025];
        Assert.Null(SensorSettingsPipeWorker.ParseStrictRequest(oversized));
    }
}
