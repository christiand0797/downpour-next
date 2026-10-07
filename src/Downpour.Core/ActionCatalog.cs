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
                AllowedObjectIdPatterns: new[] { "obj-" }),

            [ActionKinds.BlockRemoteIp] = new ActionCatalogEntry(
                ActionKind: ActionKinds.BlockRemoteIp,
                DisplayName: "Block Remote IP",
                Description: "Create inbound and outbound Windows Firewall rules to block all traffic to and from a specific remote IP address.",
                Category: "Network Protection",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 30,
                RequiredPermission: "firewall-rule-create",
                RequiredParameters: new[] { "targetIp" },
                AllowedObjectIdPatterns: new[] { "ip-", "obj-" }),

            [ActionKinds.RemoveFirewallRule] = new ActionCatalogEntry(
                ActionKind: ActionKinds.RemoveFirewallRule,
                DisplayName: "Remove Firewall Rule",
                Description: "Remove a Windows Firewall rule previously created by Downpour or legacy Downpour v29.",
                Category: "Network Protection",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 30,
                RequiredPermission: "firewall-rule-delete",
                RequiredParameters: new[] { "ruleName" },
                AllowedObjectIdPatterns: new[] { "rule-", "obj-" }),

            [ActionKinds.BlockUsbDevice] = new ActionCatalogEntry(
                ActionKind: ActionKinds.BlockUsbDevice,
                DisplayName: "Block USB Device",
                Description: "Disable a connected or recognized USB device instance node via Windows PnP and persist it in the blocked device registry.",
                Category: "Device Control",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 30,
                RequiredPermission: "device-manage",
                RequiredParameters: new[] { "deviceId" },
                AllowedObjectIdPatterns: new[] { "usb-", "obj-" }),

            [ActionKinds.UnblockUsbDevice] = new ActionCatalogEntry(
                ActionKind: ActionKinds.UnblockUsbDevice,
                DisplayName: "Unblock USB Device",
                Description: "Re-enable a blocked USB device instance node via Windows PnP and remove it from the blocked device registry.",
                Category: "Device Control",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 30,
                RequiredPermission: "device-manage",
                RequiredParameters: new[] { "deviceId" },
                AllowedObjectIdPatterns: new[] { "usb-", "obj-" }),

            [ActionKinds.SetUsbStorage] = new ActionCatalogEntry(
                ActionKind: ActionKinds.SetUsbStorage,
                DisplayName: "Configure USB Mass Storage Driver",
                Description: "Enable or disable the Windows USBSTOR service to control whether external USB mass storage devices can be mounted.",
                Category: "Device Control",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 30,
                RequiredPermission: "service-configure",
                RequiredParameters: new[] { "enabled" },
                AllowedObjectIdPatterns: new[] { "usbstor-", "obj-" }),

            [ActionKinds.IsolateHost] = new ActionCatalogEntry(
                ActionKind: ActionKinds.IsolateHost,
                DisplayName: "Host Network Isolation",
                Description: "Isolate the host by blocking all inbound and outbound network traffic via Windows Firewall with an enforced auto-expiry timer.",
                Category: "Host Containment",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 30,
                RequiredPermission: "network-isolate",
                RequiredParameters: new[] { "durationMinutes" },
                AllowedObjectIdPatterns: new[] { "host-", "obj-" }),

            [ActionKinds.ReleaseHostIsolation] = new ActionCatalogEntry(
                ActionKind: ActionKinds.ReleaseHostIsolation,
                DisplayName: "Release Host Network Isolation",
                Description: "Remove Windows Firewall isolation block rules and restore normal network connectivity.",
                Category: "Host Containment",
                EnabledByDefault: false,
                RequiresElevation: true,
                TimeoutSeconds: 30,
                RequiredPermission: "network-isolate",
                RequiredParameters: Array.Empty<string>(),
                AllowedObjectIdPatterns: new[] { "host-", "obj-" })
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
                EnabledAtUtc: null),

            [ActionKinds.BlockRemoteIp] = new FeatureSwitch(
                FeatureId: ActionKinds.BlockRemoteIp,
                DisplayName: "Firewall IP Block",
                Description: "Allow blocking malicious remote IP addresses via Windows Firewall.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.RemoveFirewallRule] = new FeatureSwitch(
                FeatureId: ActionKinds.RemoveFirewallRule,
                DisplayName: "Firewall Rule Removal",
                Description: "Allow removing Downpour and legacy Downpour v29 firewall rules.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.BlockUsbDevice] = new FeatureSwitch(
                FeatureId: ActionKinds.BlockUsbDevice,
                DisplayName: "USB Device Block",
                Description: "Allow blocking suspicious USB devices via Windows PnP.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.UnblockUsbDevice] = new FeatureSwitch(
                FeatureId: ActionKinds.UnblockUsbDevice,
                DisplayName: "USB Device Unblock",
                Description: "Allow unblocking previously blocked USB devices.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.SetUsbStorage] = new FeatureSwitch(
                FeatureId: ActionKinds.SetUsbStorage,
                DisplayName: "USB Mass Storage Toggle",
                Description: "Allow enabling or disabling the Windows USBSTOR storage driver.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.IsolateHost] = new FeatureSwitch(
                FeatureId: ActionKinds.IsolateHost,
                DisplayName: "Host Network Isolation",
                Description: "Allow emergency host network isolation with built-in auto-expiry.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null),

            [ActionKinds.ReleaseHostIsolation] = new FeatureSwitch(
                FeatureId: ActionKinds.ReleaseHostIsolation,
                DisplayName: "Release Host Isolation",
                Description: "Allow manual release of host network isolation before auto-expiry.",
                Enabled: false,
                RequiredPolicyVersion: CurrentPolicyVersion,
                EnabledAtUtc: null)
        };
    }
}
