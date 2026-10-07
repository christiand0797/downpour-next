using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Default action catalog with versioned policy definitions.
/// Actions are explicitly allow-listed; only catalog entries may be executed.
/// All actions are disabled by default and must be explicitly enabled via feature switches.
/// </summary>
public static class DefaultActionCatalog
{
    public const int SchemaVersion = 1;
    public const string CurrentPolicyVersion = "1.0.0";

    /// <summary>
    /// Gets the default action catalog snapshot.
    /// </summary>
    public static ActionCatalogSnapshot GetCatalog()
    {
        var actions = new Dictionary<string, ActionCatalogEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = new ActionCatalogEntry(
                ActionKind: ActionKinds.QuarantineFile,
                DisplayName: "Quarantine File",
                Description: "Move a suspicious file to encrypted quarantine storage and replace it with a stub.",
                Category: "File System",
                EnabledByDefault: false,
                RequiresElevation: false,
                TimeoutSeconds: 30,
                RequiredPermission: "file-write",
                RequiredParameters: new[] { "sourcePath", "expectedHash" },
                AllowedObjectIdPatterns: new[] { "obj-" }), // All obj- IDs are allowed for now

            [ActionKinds.RestoreFile] = new ActionCatalogEntry(
                ActionKind: ActionKinds.RestoreFile,
                DisplayName: "Restore File",
                Description: "Restore a quarantined file from encrypted storage to its original location.",
                Category: "File System",
                EnabledByDefault: false,
                RequiresElevation: false,
                TimeoutSeconds: 30,
                RequiredPermission: "file-write",
                RequiredParameters: new[] { "sourcePath", "quarantineId" },
                AllowedObjectIdPatterns: new[] { "obj-" }),

            [ActionKinds.TerminateProcess] = new ActionCatalogEntry(
                ActionKind: ActionKinds.TerminateProcess,
                DisplayName: "Terminate Process",
                Description: "Terminate an evasive or suspicious process named in an open security alert.",
                Category: "Process Management",
                EnabledByDefault: false,
                RequiresElevation: false,
                TimeoutSeconds: 15,
                RequiredPermission: "process-terminate",
                RequiredParameters: new[] { "processId", "startTimeUtc" },
                AllowedObjectIdPatterns: new[] { "obj-" })
        };

        return new ActionCatalogSnapshot(
            SchemaVersion,
            DateTimeOffset.UtcNow,
            actions,
            CurrentPolicyVersion);
    }

    /// <summary>
    /// Gets the default feature switches. All actions are disabled by default.
    /// </summary>
    public static IReadOnlyDictionary<string, FeatureSwitch> GetDefaultFeatureSwitches()
    {
        return new Dictionary<string, FeatureSwitch>(StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = new FeatureSwitch(
                FeatureId: ActionKinds.QuarantineFile,
                DisplayName: "File Quarantine",
                Description: "Allow quarantining suspicious files to encrypted storage.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.RestoreFile] = new FeatureSwitch(
                FeatureId: ActionKinds.RestoreFile,
                DisplayName: "File Restore",
                Description: "Allow restoring quarantined files from encrypted storage.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.TerminateProcess] = new FeatureSwitch(
                FeatureId: ActionKinds.TerminateProcess,
                DisplayName: "Process Termination",
                Description: "Allow terminating suspicious processes associated with verified security alerts.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null)
        };
    }
}
