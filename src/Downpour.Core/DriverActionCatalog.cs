using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Default driver action catalog with versioned policy definitions.
/// Actions are explicitly allow-listed; only catalog entries may be executed.
/// All actions are disabled by default and must be explicitly enabled via feature switches.
/// </summary>
public static class DefaultDriverActionCatalog
{
    public const int SchemaVersion = 1;
    public const string CurrentPolicyVersion = "1.0.0";

    /// <summary>
    /// Gets the default driver action catalog snapshot.
    /// </summary>
    public static DriverActionCatalogSnapshot GetCatalog()
    {
        var actions = new Dictionary<string, DriverActionCatalogEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [DriverActionKinds.InstallDriver] = new DriverActionCatalogEntry(
                ActionKind: DriverActionKinds.InstallDriver,
                DisplayName: "Install Driver",
                Description: "Install a driver package from an INF file with signature verification.",
                Category: "Driver Management",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 60,
                RequiredPermission: "driver-install",
                RequiredParameters: new[] { "infFilePath", "targetHardwareId" }),

            [DriverActionKinds.UpdateDriver] = new DriverActionCatalogEntry(
                ActionKind: DriverActionKinds.UpdateDriver,
                DisplayName: "Update Driver",
                Description: "Update an existing driver package with signature verification.",
                Category: "Driver Management",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 60,
                RequiredPermission: "driver-update",
                RequiredParameters: new[] { "infFilePath", "targetHardwareId" }),

            [DriverActionKinds.UninstallDriver] = new DriverActionCatalogEntry(
                ActionKind: DriverActionKinds.UninstallDriver,
                DisplayName: "Uninstall Driver",
                Description: "Uninstall a driver package with rollback capability.",
                Category: "Driver Management",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 60,
                RequiredPermission: "driver-uninstall",
                RequiredParameters: new[] { "infFilePath", "targetHardwareId" }),

            [DriverActionKinds.ExportDriver] = new DriverActionCatalogEntry(
                ActionKind: DriverActionKinds.ExportDriver,
                DisplayName: "Export Driver",
                Description: "Export a driver package to a specified location for backup.",
                Category: "Driver Management",
                EnabledByDefault: false,
                RequiresElevation: false,
                TimeoutSeconds: 30,
                RequiredPermission: "driver-export",
                RequiredParameters: new[] { "infFilePath", "exportPath" }),

            [DriverActionKinds.RollbackDriver] = new DriverActionCatalogEntry(
                ActionKind: DriverActionKinds.RollbackDriver,
                DisplayName: "Rollback Driver",
                Description: "Rollback a driver to the previously installed version.",
                Category: "Driver Management",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 60,
                RequiredPermission: "driver-rollback",
                RequiredParameters: new[] { "infFilePath", "targetHardwareId" })
        };

        return new DriverActionCatalogSnapshot(
            SchemaVersion,
            DateTimeOffset.UtcNow,
            actions,
            CurrentPolicyVersion);
    }

    /// <summary>
    /// Gets the default driver feature switches. All actions are disabled by default.
    /// </summary>
    public static IReadOnlyDictionary<string, FeatureSwitch> GetDefaultFeatureSwitches()
    {
        return new Dictionary<string, FeatureSwitch>(StringComparer.OrdinalIgnoreCase)
        {
            [DriverActionKinds.InstallDriver] = new FeatureSwitch(
                FeatureId: DriverActionKinds.InstallDriver,
                DisplayName: "Driver Install",
                Description: "Allow installing driver packages with signature verification.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [DriverActionKinds.UpdateDriver] = new FeatureSwitch(
                FeatureId: DriverActionKinds.UpdateDriver,
                DisplayName: "Driver Update",
                Description: "Allow updating driver packages with signature verification.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [DriverActionKinds.UninstallDriver] = new FeatureSwitch(
                FeatureId: DriverActionKinds.UninstallDriver,
                DisplayName: "Driver Uninstall",
                Description: "Allow uninstalling driver packages with rollback capability.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [DriverActionKinds.ExportDriver] = new FeatureSwitch(
                FeatureId: DriverActionKinds.ExportDriver,
                DisplayName: "Driver Export",
                Description: "Allow exporting driver packages for backup.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [DriverActionKinds.RollbackDriver] = new FeatureSwitch(
                FeatureId: DriverActionKinds.RollbackDriver,
                DisplayName: "Driver Rollback",
                Description: "Allow rolling back drivers to previous versions.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null)
        };
    }
}
