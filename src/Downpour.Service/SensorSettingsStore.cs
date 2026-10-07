using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>
/// Persisted service-side sensor settings in the ACL-protected state folder. Defaults follow the owner's decisions in
/// SECURITY.md: script-block analysis, automatic intel lookups (inert until a key is configured), and confirmed quarantine actions are on.
/// </summary>
public sealed class SensorSettingsStore(string path)
{
    public static readonly SensorSettingsSnapshot Defaults = new(1, ScriptBlockAnalysis: true, IntelLookups: true);
    private const long MaximumBytes = 4096;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();
    private SensorSettingsSnapshot? _current;

    public event Action<SensorSettingsSnapshot>? Changed;

    public static SensorSettingsStore CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var file = Path.Combine(root, "sensor-settings.v1.json");
        SecureJournalDirectory.RestrictExistingFile(file);
        return new SensorSettingsStore(file);
    }

    public SensorSettingsSnapshot Current
    {
        get
        {
            lock (_gate) return _current ??= Load();
        }
    }

    public SensorSettingResponse Apply(SensorSettingRequest request)
    {
        if (request.SchemaVersion != 1 || request.RequestId == Guid.Empty)
            return new(1, request.RequestId, false, "invalid-request", null);
        if (request.Key == SensorSettingKeys.Get)
            return new(1, request.RequestId, true, "current", Current);
        if (!SensorSettingKeys.Writable.Contains(request.Key))
            return new(1, request.RequestId, false, "invalid-request", null);

        SensorSettingsSnapshot updated;
        lock (_gate)
        {
            var current = _current ??= Load();
            updated = request.Key switch
            {
                SensorSettingKeys.ScriptBlockAnalysis => current with { ScriptBlockAnalysis = request.Value },
                SensorSettingKeys.QuarantineActions => current with { QuarantineActions = request.Value },
                SensorSettingKeys.ProcessTerminationActions => current with { ProcessTerminationActions = request.Value },
                SensorSettingKeys.FirewallActions => current with { FirewallActions = request.Value },
                SensorSettingKeys.UsbActions => current with { UsbActions = request.Value },
                _ => current with { IntelLookups = request.Value },
            };
            if (updated == current) return new(1, request.RequestId, true, "unchanged", current);
            if (!Save(updated)) return new(1, request.RequestId, false, "storage-failed", current);
            _current = updated;
        }
        Changed?.Invoke(updated);
        return new(1, request.RequestId, true, "updated", updated);
    }

    private SensorSettingsSnapshot Load()
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaximumBytes || (info.Attributes & FileAttributes.ReparsePoint) != 0) return Defaults;
            var loaded = JsonSerializer.Deserialize<SensorSettingsSnapshot>(File.ReadAllBytes(path), Json);
            return loaded is { SchemaVersion: 1 } ? loaded : Defaults;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return Defaults;
        }
    }

    private bool Save(SensorSettingsSnapshot settings)
    {
        var temporary = path + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(settings, Json));
            File.Move(temporary, path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            return false;
        }
    }
}
