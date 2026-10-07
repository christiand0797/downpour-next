namespace Downpour.Contracts;

/// <summary>Service-side sensor settings that affect what data the service reads. See SECURITY.md "User-approved data handling".</summary>
public sealed record SensorSettingsSnapshot(int SchemaVersion, bool ScriptBlockAnalysis, bool IntelLookups, IReadOnlyList<string>? IntelServicesConfigured = null, bool QuarantineActions = true, bool ProcessTerminationActions = true, bool FirewallActions = true, bool UsbActions = true);

/// <summary>
/// Reads settings (Key = "get"), sets one allow-listed boolean key, or for "apiKey.{service}" keys stores
/// <see cref="Secret"/> (Value true) or removes the key (Value false).
/// </summary>
public sealed record SensorSettingRequest(int SchemaVersion, Guid RequestId, string Key, bool Value, string? Secret = null);

public sealed record SensorSettingResponse(int SchemaVersion, Guid RequestId, bool Accepted, string ResultCode, SensorSettingsSnapshot? Settings);

public static class SensorSettingKeys
{
    public const string Get = "get";
    public const string ScriptBlockAnalysis = "scriptBlockAnalysis";
    public const string IntelLookups = "intelLookups";
    public const string QuarantineActions = "quarantineActions";
    public const string ProcessTerminationActions = "processTerminationActions";
    public const string FirewallActions = "firewallActions";
    public const string UsbActions = "usbActions";

    public static readonly IReadOnlySet<string> Writable = new HashSet<string>(StringComparer.Ordinal) { ScriptBlockAnalysis, IntelLookups, QuarantineActions, ProcessTerminationActions, FirewallActions, UsbActions };
    public const string ApiKeyPrefix = "apiKey.";

    public static string ApiKey(string service) => ApiKeyPrefix + service;

    public static bool IsApiKey(string key, out string service)
    {
        service = key.StartsWith(ApiKeyPrefix, StringComparison.Ordinal) ? key[ApiKeyPrefix.Length..] : "";
        return IntelServices.All.Contains(service);
    }
}
