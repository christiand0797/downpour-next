using System.Runtime.InteropServices;
using Windows.Foundation.Collections;
using Windows.Storage;

namespace Downpour_Desktop;

/// <summary>Small, non-sensitive per-user preferences stored in the packaged app's local settings.</summary>
public static class AppPreferences
{
    private const string Prefix = "Downpour.Next.Preferences.v1.";
    private static bool _loaded;
    private static bool _rainEffectsEnabled = true;
    private static bool _reduceMotion;
    private static bool _autoStormCycle = true;
    private static bool _usePortableSettingsFile;

    public static event Action? Changed;
    public static bool PersistenceAvailable { get; private set; } = true;

    public static bool RainEffectsEnabled
    {
        get => _rainEffectsEnabled;
        set => Set(ref _rainEffectsEnabled, value, "rainEffectsEnabled");
    }

    public static bool ReduceMotion
    {
        get => _reduceMotion;
        set => Set(ref _reduceMotion, value, "reduceMotion");
    }

    public static bool AutoStormCycle
    {
        get => _autoStormCycle;
        set => Set(ref _autoStormCycle, value, "autoStormCycle");
    }

    public static void Load()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            var values = ApplicationData.Current.LocalSettings.Values;
            _rainEffectsEnabled = Read(values, "rainEffectsEnabled", true);
            _reduceMotion = Read(values, "reduceMotion", false);
            _autoStormCycle = Read(values, "autoStormCycle", true);
            PersistenceAvailable = true;
        }
        catch (Exception exception) when (IsStorageUnavailable(exception))
        {
            _usePortableSettingsFile = true;
            try
            {
                var values = ReadPortableSettings();
                _rainEffectsEnabled = values.Rain;
                _reduceMotion = values.ReduceMotion;
                _autoStormCycle = values.AutoCycle;
                PersistenceAvailable = true;
            }
            catch (Exception fileException) when (fileException is IOException or UnauthorizedAccessException or ArgumentException)
            {
                PersistenceAvailable = false;
            }
        }
    }

    private static bool Read(IPropertySet values, string key, bool fallback) =>
        values.TryGetValue(Prefix + key, out var stored) && stored is bool value ? value : fallback;

    private static void Set(ref bool field, bool value, string key)
    {
        if (field == value) return;
        field = value;
        if (_usePortableSettingsFile)
        {
            PersistPortableSettings();
        }
        else
        {
            try
            {
                ApplicationData.Current.LocalSettings.Values[Prefix + key] = value;
                PersistenceAvailable = true;
            }
            catch (Exception exception) when (IsStorageUnavailable(exception))
            {
                _usePortableSettingsFile = true;
                PersistPortableSettings();
            }
        }
        Changed?.Invoke();
    }

    private static bool IsStorageUnavailable(Exception exception) =>
        exception is InvalidOperationException or UnauthorizedAccessException or COMException;

    private static (bool Rain, bool ReduceMotion, bool AutoCycle) ReadPortableSettings()
    {
        var path = GetPortableSettingsPath();
        if (!File.Exists(path)) return (true, false, true);
        if (new FileInfo(path).Length > 4096) throw new InvalidDataException("The local preferences file exceeds its size limit.");
        var values = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadLines(path).Take(16))
        {
            var separator = line.IndexOf('=');
            if (separator <= 0 || separator == line.Length - 1) continue;
            if (bool.TryParse(line[(separator + 1)..].Trim(), out var value))
                values[line[..separator].Trim()] = value;
        }
        return (
            values.GetValueOrDefault("RainEffectsEnabled", true),
            values.GetValueOrDefault("ReduceMotion", false),
            values.GetValueOrDefault("AutoStormCycle", true));
    }

    private static void PersistPortableSettings()
    {
        try
        {
            var path = GetPortableSettingsPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllLines(path,
            [
                $"RainEffectsEnabled={_rainEffectsEnabled}",
                $"ReduceMotion={_reduceMotion}",
                $"AutoStormCycle={_autoStormCycle}"
            ]);
            PersistenceAvailable = true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            PersistenceAvailable = false;
        }
    }

    private static string GetPortableSettingsPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "preferences.v1.ini");
}
