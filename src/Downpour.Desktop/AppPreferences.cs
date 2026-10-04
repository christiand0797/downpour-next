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
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException or COMException)
        {
            PersistenceAvailable = false;
        }
    }

    private static bool Read(IPropertySet values, string key, bool fallback) =>
        values.TryGetValue(Prefix + key, out var stored) && stored is bool value ? value : fallback;

    private static void Set(ref bool field, bool value, string key)
    {
        if (field == value) return;
        field = value;
        try
        {
            ApplicationData.Current.LocalSettings.Values[Prefix + key] = value;
            PersistenceAvailable = true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException or COMException)
        {
            PersistenceAvailable = false;
        }
        Changed?.Invoke();
    }
}
