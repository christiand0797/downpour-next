using System.Runtime.InteropServices;
using Windows.Foundation.Collections;
using Windows.Storage;

namespace Downpour_Desktop;

/// <summary>Small, non-sensitive per-user preferences stored in the packaged app's local settings.</summary>
public static class AppPreferences
{
    private const string Prefix = "Downpour.Next.Preferences.v1.";

    // Name, default. Defaults for alerts follow v29: minimize_to_tray=true, sound alarm off with a CRITICAL threshold.
    private static readonly (string Key, bool Default)[] Definitions =
    [
        ("rainEffectsEnabled", true),
        ("reduceMotion", false),
        ("autoStormCycle", true),
        ("notificationsEnabled", true),
        ("minimizeToTray", true),
        ("soundAlarmEnabled", false),
        ("soundAlarmIncludesHigh", false),
        ("ransomwareContentSampling", true),
        ("setupPermissionsSeen", false),
        ("setupQuietPeriodSeen", false),
    ];

    /// <summary>
    /// The switches a portable bundle may carry. The setup acknowledgements are deliberately absent: they record that
    /// this person saw an explanation on this PC, which is not true on the PC the bundle is carried to.
    /// </summary>
    private static readonly string[] PortableKeys =
    [
        "rainEffectsEnabled",
        "reduceMotion",
        "autoStormCycle",
        "notificationsEnabled",
        "minimizeToTray",
        "soundAlarmEnabled",
        "soundAlarmIncludesHigh",
        "ransomwareContentSampling",
    ];

    private static readonly Dictionary<string, bool> Values = Definitions.ToDictionary(d => d.Key, d => d.Default, StringComparer.Ordinal);
    private static bool _loaded;
    private static bool _usePortableSettingsFile;

    public static event Action? Changed;
    public static bool PersistenceAvailable { get; private set; } = true;

    public static bool RainEffectsEnabled { get => Values["rainEffectsEnabled"]; set => Set("rainEffectsEnabled", value); }
    public static bool ReduceMotion { get => Values["reduceMotion"]; set => Set("reduceMotion", value); }
    public static bool AutoStormCycle { get => Values["autoStormCycle"]; set => Set("autoStormCycle", value); }
    public static bool NotificationsEnabled { get => Values["notificationsEnabled"]; set => Set("notificationsEnabled", value); }
    public static bool MinimizeToTray { get => Values["minimizeToTray"]; set => Set("minimizeToTray", value); }
    public static bool SoundAlarmEnabled { get => Values["soundAlarmEnabled"]; set => Set("soundAlarmEnabled", value); }
    public static bool SoundAlarmIncludesHigh { get => Values["soundAlarmIncludesHigh"]; set => Set("soundAlarmIncludesHigh", value); }
    public static bool RansomwareContentSampling { get => Values["ransomwareContentSampling"]; set => Set("ransomwareContentSampling", value); }

    /// <summary>The person has seen why administrator access changes what can be read; not a claim that elevation exists.</summary>
    public static bool SetupPermissionsSeen { get => Values["setupPermissionsSeen"]; set => Set("setupPermissionsSeen", value); }

    /// <summary>The person has seen the expected-quiet-start explanation.</summary>
    public static bool SetupQuietPeriodSeen { get => Values["setupQuietPeriodSeen"]; set => Set("setupQuietPeriodSeen", value); }

    public static void Load()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            var stored = ApplicationData.Current.LocalSettings.Values;
            foreach (var (key, fallback) in Definitions) Values[key] = Read(stored, key, fallback);
            PersistenceAvailable = true;
        }
        catch (Exception exception) when (IsStorageUnavailable(exception))
        {
            _usePortableSettingsFile = true;
            try
            {
                foreach (var (key, value) in ReadPortableSettings()) Values[key] = value;
                PersistenceAvailable = true;
            }
            catch (Exception fileException) when (fileException is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
            {
                PersistenceAvailable = false;
            }
        }
    }

    /// <summary>The preference names a bundle uses, in the same PascalCase form as the local preferences file.</summary>
    public static IReadOnlyList<string> PortableNames { get; } = PortableKeys.Select(FileKey).ToArray();

    /// <summary>A copy of the portable switches, so an export cannot observe a value change halfway through.</summary>
    public static IReadOnlyDictionary<string, bool> ReadPortableValues() =>
        PortableKeys.ToDictionary(FileKey, key => Values[key], StringComparer.Ordinal);

    /// <summary>
    /// Applies known portable switches and returns how many actually changed. Unknown names are skipped here; the bundle
    /// reader refuses a whole document that names one before this is reached.
    /// </summary>
    public static int ApplyPortableValues(IReadOnlyDictionary<string, bool> values)
    {
        var applied = 0;
        foreach (var pair in values)
        {
            var key = PortableKeys.FirstOrDefault(candidate => string.Equals(FileKey(candidate), pair.Key, StringComparison.Ordinal));
            if (key is null || Values[key] == pair.Value) continue;
            Set(key, pair.Value);
            applied++;
        }
        return applied;
    }

    private static bool Read(IPropertySet values, string key, bool fallback) =>
        values.TryGetValue(Prefix + key, out var stored) && stored is bool value ? value : fallback;

    private static void Set(string key, bool value)
    {
        if (Values[key] == value) return;
        Values[key] = value;
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

    /// <summary>Reads known keys only. File keys use PascalCase (RainEffectsEnabled=...) for compatibility with earlier files.</summary>
    private static IEnumerable<(string Key, bool Value)> ReadPortableSettings()
    {
        var path = GetPortableSettingsPath();
        if (!File.Exists(path)) yield break;
        if (new FileInfo(path).Length > 4096) throw new InvalidDataException("The local preferences file exceeds its size limit.");
        var known = Definitions.ToDictionary(d => FileKey(d.Key), d => d.Key, StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadLines(path).Take(32))
        {
            var separator = line.IndexOf('=');
            if (separator <= 0 || separator == line.Length - 1) continue;
            if (known.TryGetValue(line[..separator].Trim(), out var key) && bool.TryParse(line[(separator + 1)..].Trim(), out var value))
                yield return (key, value);
        }
    }

    private static void PersistPortableSettings()
    {
        try
        {
            var path = GetPortableSettingsPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllLines(path, Definitions.Select(d => $"{FileKey(d.Key)}={Values[d.Key]}"));
            PersistenceAvailable = true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            PersistenceAvailable = false;
        }
    }

    private static string FileKey(string key) => char.ToUpperInvariant(key[0]) + key[1..];

    private static string GetPortableSettingsPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "preferences.v1.ini");
}
