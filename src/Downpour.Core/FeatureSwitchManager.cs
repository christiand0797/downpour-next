using Downpour.Contracts;
using System.Text.Json;

namespace Downpour.Core;

/// <summary>
/// Manages feature switch state with local persistence.
/// Feature switches control whether specific actions are enabled.
/// All actions are disabled by default and must be explicitly enabled.
/// </summary>
public sealed class FeatureSwitchManager
{
    private const int CurrentSchemaVersion = 1;
    private const string FeatureSwitchFileName = "feature-switches.json";
    private readonly string _storagePath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public FeatureSwitchManager(string storagePath)
    {
        _storagePath = storagePath ?? throw new ArgumentNullException(nameof(storagePath));
    }

    /// <summary>
    /// Creates a feature switch manager for the current user's local app data.
    /// </summary>
    public static FeatureSwitchManager CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext");
        Directory.CreateDirectory(root);
        var storagePath = Path.Combine(root, FeatureSwitchFileName);
        return new FeatureSwitchManager(storagePath);
    }

    /// <summary>
    /// Loads feature switches from persistent storage, merging with defaults.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, FeatureSwitch>> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await LoadCoreAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Enables or disables a feature switch with audit logging.
    /// </summary>
    public async Task<bool> SetEnabledAsync(string featureId, bool enabled, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(featureId))
            throw new ArgumentException("Feature ID cannot be empty.", nameof(featureId));

        await _gate.WaitAsync(cancellationToken);
        try
        {
            // Do not call LoadAsync here: it also acquires _gate and would deadlock.
            var current = await LoadCoreAsync(cancellationToken);
            if (!current.TryGetValue(featureId, out var currentSwitch))
            {
                return false; // Feature does not exist
            }

            if (currentSwitch.Enabled == enabled)
            {
                return true; // No change needed
            }

            var updated = currentSwitch with
            {
                Enabled = enabled,
                EnabledAtUtc = enabled ? DateTimeOffset.UtcNow : null
            };

            var updatedDict = new Dictionary<string, FeatureSwitch>(current, StringComparer.OrdinalIgnoreCase);
            updatedDict[featureId] = updated;

            var persisted = new FeatureSwitchPersisted
            {
                SchemaVersion = CurrentSchemaVersion,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Switches = updatedDict
            };

            var parentDirectory = Path.GetDirectoryName(_storagePath);
            if (!string.IsNullOrEmpty(parentDirectory))
            {
                Directory.CreateDirectory(parentDirectory);
            }

            var json = JsonSerializer.Serialize(persisted, _jsonOptions);
            await File.WriteAllTextAsync(_storagePath, json, cancellationToken);

            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    // Caller must hold _gate. Keeping this unguarded method separate lets updates
    // perform a read/modify/write under one lock without recursively waiting.
    private async Task<IReadOnlyDictionary<string, FeatureSwitch>> LoadCoreAsync(CancellationToken cancellationToken)
    {
        var defaults = DefaultActionCatalog.GetDefaultFeatureSwitches();
        if (!File.Exists(_storagePath))
        {
            return defaults;
        }

        FeatureSwitchPersisted? persisted;
        try
        {
            var json = await File.ReadAllTextAsync(_storagePath, cancellationToken);
            persisted = JsonSerializer.Deserialize<FeatureSwitchPersisted>(json, _jsonOptions);
        }
        catch (JsonException)
        {
            // Corrupt persisted state must not enable any action.
            return defaults;
        }

        if (persisted == null || persisted.SchemaVersion != CurrentSchemaVersion || persisted.Switches == null)
        {
            return defaults;
        }

        var merged = new Dictionary<string, FeatureSwitch>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, defaultSwitch) in defaults)
        {
            if (persisted.Switches.TryGetValue(key, out var persistedSwitch)
                && persistedSwitch != null
                && string.Equals(persistedSwitch.FeatureId, key, StringComparison.OrdinalIgnoreCase)
                && string.Equals(persistedSwitch.RequiredPolicyVersion, defaultSwitch.RequiredPolicyVersion, StringComparison.Ordinal))
            {
                merged[key] = persistedSwitch;
            }
            else
            {
                // New, malformed, or stale entries use the default-off policy.
                merged[key] = defaultSwitch with { Enabled = false, EnabledAtUtc = null };
            }
        }

        return merged;
    }

    private sealed class FeatureSwitchPersisted
    {
        public int SchemaVersion { get; set; }
        public DateTimeOffset UpdatedAtUtc { get; set; }
        public Dictionary<string, FeatureSwitch>? Switches { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
