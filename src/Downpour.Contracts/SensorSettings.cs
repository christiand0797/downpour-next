namespace Downpour.Contracts;

/// <summary>Service-side sensor settings that affect what data the service reads. See SECURITY.md "User-approved data handling".</summary>
public sealed record SensorSettingsSnapshot(int SchemaVersion, bool ScriptBlockAnalysis, bool IntelLookups);

/// <summary>Reads settings (Key = "get") or sets one allow-listed boolean key.</summary>
public sealed record SensorSettingRequest(int SchemaVersion, Guid RequestId, string Key, bool Value);

public sealed record SensorSettingResponse(int SchemaVersion, Guid RequestId, bool Accepted, string ResultCode, SensorSettingsSnapshot? Settings);

public static class SensorSettingKeys
{
    public const string Get = "get";
    public const string ScriptBlockAnalysis = "scriptBlockAnalysis";
    public const string IntelLookups = "intelLookups";

    public static readonly IReadOnlySet<string> Writable = new HashSet<string>(StringComparer.Ordinal) { ScriptBlockAnalysis, IntelLookups };
}
