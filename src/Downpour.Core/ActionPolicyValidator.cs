using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Validates action requests against policy constraints, feature switches, and allow-lists.
/// This enforces default-deny: no action executes unless explicitly authorized by policy and user consent.
/// </summary>
public sealed class ActionPolicyValidator
{
    private readonly ActionCatalogSnapshot _catalog;
    private readonly IReadOnlyDictionary<string, FeatureSwitch> _featureSwitches;
    private readonly string _currentPolicyVersion;

    public ActionPolicyValidator(
        ActionCatalogSnapshot catalog,
        IReadOnlyDictionary<string, FeatureSwitch> featureSwitches,
        string currentPolicyVersion)
    {
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _featureSwitches = featureSwitches ?? throw new ArgumentNullException(nameof(featureSwitches));
        _currentPolicyVersion = currentPolicyVersion ?? throw new ArgumentNullException(nameof(currentPolicyVersion));
    }

    /// <summary>
    /// Validates an action request against all policy constraints.
    /// </summary>
    public ActionPolicyValidation Validate(ActionRequest request) => Validate(request, requireConsent: true);

    private ActionPolicyValidation Validate(ActionRequest request, bool requireConsent)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var violations = new List<string>();
        var warnings = new List<string>();
        var permissionRejected = false;

        // Check schema version
        if (request.SchemaVersion != 1)
        {
            violations.Add($"Unsupported schema version {request.SchemaVersion}; expected 1.");
            return new ActionPolicyValidation(false, "schema-version-unsupported", violations, warnings);
        }

        // Check if action kind exists in catalog
        if (!_catalog.Actions.TryGetValue(request.ActionKind, out var catalogEntry))
        {
            violations.Add($"Action kind '{request.ActionKind}' is not in the allow-list catalog.");
            return new ActionPolicyValidation(false, "action-kind-not-allowed", violations, warnings);
        }

        // Check feature switch (default-deny)
        if (!_featureSwitches.TryGetValue(request.ActionKind, out var featureSwitch) || !featureSwitch.Enabled)
        {
            violations.Add($"Action kind '{request.ActionKind}' is disabled by feature switch.");
            return new ActionPolicyValidation(false, ActionResultCodes.RejectedFeatureDisabled, violations, warnings);
        }

        // Check policy version
        if (request.PolicyVersion != _currentPolicyVersion)
        {
            violations.Add($"Policy version mismatch: request '{request.PolicyVersion}' vs current '{_currentPolicyVersion}'.");
            return new ActionPolicyValidation(false, "policy-version-mismatch", violations, warnings);
        }

        // Check required parameters
        foreach (var requiredParam in catalogEntry.RequiredParameters)
        {
            if (!request.Parameters.ContainsKey(requiredParam))
            {
                violations.Add($"Missing required parameter: {requiredParam}.");
            }
        }

        // Check object ID format (must match obj- + 32 hex chars pattern from journal)
        if (!IsValidObjectId(request.ObjectId))
        {
            violations.Add("Object ID must use the 'obj-' + 32 lowercase hexadecimal characters format.");
        }

        // Check object ID against allowed patterns
        bool patternMatched = false;
        foreach (var pattern in catalogEntry.AllowedObjectIdPatterns)
        {
            if (IsPatternMatch(request.ObjectId, pattern))
            {
                patternMatched = true;
                break;
            }
        }
        if (!patternMatched && catalogEntry.AllowedObjectIdPatterns.Count > 0)
        {
            violations.Add($"Object ID '{request.ObjectId}' does not match any allowed pattern.");
        }

        // Non-dry-run requests need an explicit consent signal and operator identity.
        // The service must still bind this identity to its authenticated IPC caller.
        if (requireConsent && !request.DryRun && !request.UserConsentGiven)
        {
            violations.Add("Explicit user consent is required for a non-dry-run action request.");
            permissionRejected = true;
        }
        if (requireConsent && !request.DryRun && string.IsNullOrWhiteSpace(request.UserSid))
        {
            violations.Add("An operator user SID is required for a consented action request.");
            permissionRejected = true;
        }

        // Validate that dry-run requests are not rejected
        if (request.DryRun)
        {
            warnings.Add("Request is a dry-run; no system changes will be applied.");
        }

        if (violations.Count > 0)
        {
            return new ActionPolicyValidation(false,
                permissionRejected ? ActionResultCodes.RejectedPermission : ActionResultCodes.RejectedPolicy,
                violations,
                warnings);
        }

        return new ActionPolicyValidation(true, null, violations, warnings);
    }

    /// <summary>
    /// Generates a preview of what the action would do, for user consent dialogs.
    /// </summary>
    public ActionPreview GeneratePreview(ActionRequest request)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        // Preview is the pre-consent step, so validate policy while intentionally
        // deferring the consent requirement until a real action request is submitted.
        var validation = Validate(request, requireConsent: false);
        if (!validation.Valid)
        {
            throw new InvalidOperationException($"Cannot generate preview for invalid request: {validation.RejectionReason}");
        }

        var catalogEntry = _catalog.Actions[request.ActionKind];

        var effects = new List<string>();
        var risks = new List<string>();
        var rollbackSteps = new List<string>();

        switch (request.ActionKind)
        {
            case ActionKinds.QuarantineFile:
                effects.Add($"Move file from '{request.ObjectId}' to encrypted quarantine storage");
                effects.Add("Replace original file with a stub containing quarantine metadata");
                effects.Add("Record operation in the audit journal");
                risks.Add("If quarantine fails, the file may remain in its original location");
                risks.Add("If journal write fails, recovery may be incomplete");
                rollbackSteps.Add("Verify file hash matches the recorded quarantine hash");
                rollbackSteps.Add("Restore file from encrypted quarantine storage");
                rollbackSteps.Add("Remove quarantine stub and restore original file");
                break;

            case ActionKinds.RestoreFile:
                effects.Add($"Restore file from quarantine to '{request.ObjectId}'");
                effects.Add("Verify hash integrity before restoration");
                effects.Add("Record operation in the audit journal");
                risks.Add("If the original location is now occupied, restore may fail");
                risks.Add("If hash verification fails, file will not be restored");
                rollbackSteps.Add("Quarantine the file again if restore is incomplete");
                break;

            case ActionKinds.TerminateProcess:
                effects.Add($"Terminate running process with PID {request.ObjectId}");
                effects.Add("Halt all threads and reclaim allocated process memory");
                effects.Add("Record termination outcome in the append-only action audit log");
                risks.Add("Terminating a process may cause unsaved data loss in the target application");
                risks.Add("Terminating an unverified process can disrupt dependent background services");
                rollbackSteps.Add("Process termination is irreversible; restarted instances must be launched manually by the user");
                break;

            case ActionKinds.BlockRemoteIp:
                effects.Add($"Create inbound and outbound Windows Firewall rules blocking remote IP '{request.ObjectId}'");
                effects.Add("Drop all network packets to and from the target address across all network profiles");
                effects.Add("Record firewall rule creation and duration in the append-only action audit log");
                risks.Add("Any legitimate service or website hosted at the target IP will become unreachable");
                risks.Add("If the target is a shared CDN or cloud provider, other co-hosted services may be affected");
                rollbackSteps.Add("Remove the created firewall rules via the Firewall management page or wait for rule expiration");
                break;

            case ActionKinds.RemoveFirewallRule:
                effects.Add($"Remove Downpour Windows Firewall rule '{request.ObjectId}'");
                effects.Add("Restore standard network filtering behavior for matching network traffic");
                effects.Add("Record firewall rule deletion in the append-only action audit log");
                risks.Add("If the rule was actively blocking malicious traffic, that traffic will no longer be dropped");
                rollbackSteps.Add("Re-create the firewall block rule if network traffic remains suspicious");
                break;

            case ActionKinds.BlockUsbDevice:
                effects.Add($"Disable Windows PnP device node for USB device '{request.ObjectId}'");
                effects.Add("Add device identifier to Downpour persistent blocked device store");
                effects.Add("Prevent device from functioning until explicitly unblocked by an operator");
                effects.Add("Record device blocking event in the append-only action audit log");
                risks.Add("The device will immediately stop responding and become unusable");
                risks.Add("Any pending I/O or unsaved data transfers to the device will fail");
                rollbackSteps.Add("Unblock the device via Downpour USB Device management page or re-enable the device in Device Manager");
                break;

            case ActionKinds.UnblockUsbDevice:
                effects.Add($"Re-enable Windows PnP device node for USB device '{request.ObjectId}'");
                effects.Add("Remove device identifier from Downpour persistent blocked device store");
                effects.Add("Allow Windows to initialize and communicate with the device");
                effects.Add("Record device unblocking event in the append-only action audit log");
                risks.Add("If the device is malicious (e.g. BadUSB/Rubber Ducky/infected media), it may execute unauthorized payloads upon activation");
                rollbackSteps.Add("Block the USB device again if unauthorized activity or malicious hardware is observed");
                break;

            case ActionKinds.SetUsbStorage:
                effects.Add("Configure Windows USBSTOR storage driver start state");
                effects.Add("Record USB storage policy update in the append-only action audit log");
                risks.Add("Disabling USB storage prevents all standard USB flash drives and external hard drives from mounting");
                rollbackSteps.Add("Re-enable the USBSTOR service via Downpour USB settings or Windows Services");
                break;

            case ActionKinds.IsolateHost:
                effects.Add("Create inbound and outbound Windows Firewall isolation rules dropping all non-loopback network packets across all profiles");
                effects.Add("Preserve local loopback traffic (127.0.0.1 and ::1) to ensure local IPC remains functional");
                effects.Add("Engage automatic expiration timer to guarantee host network isolation automatically terminates");
                effects.Add("Record host isolation event and expiration time in the append-only action audit log");
                risks.Add("All external network connectivity, internet access, LAN communication, and remote access sessions will be severed immediately");
                risks.Add("Active network connections will drop and cloud-dependent services will stop responding until isolation releases");
                rollbackSteps.Add("Isolation automatically expires; operator can also manually release isolation at any time via Emergency or Remediation page");
                break;

            case ActionKinds.ReleaseHostIsolation:
                effects.Add("Remove Windows Firewall host isolation rules across all network profiles");
                effects.Add("Cancel active automatic expiration timer");
                effects.Add("Restore standard inbound and outbound network connectivity");
                effects.Add("Record isolation release event in the append-only action audit log");
                risks.Add("If active malware or threat remains on the host, command-and-control communication may resume upon reconnection");
                rollbackSteps.Add("Re-engage emergency host isolation if active malicious traffic or exfiltration continues");
                break;

            default:
                effects.Add($"Execute action '{request.ActionKind}' on '{request.ObjectId}'");
                risks.Add("Action-specific risks not yet documented");
                rollbackSteps.Add("Refer to action-specific rollback procedure");
                break;
        }

        return new ActionPreview(
            request.ActionKind,
            catalogEntry.DisplayName,
            request.ObjectId,
            request.Parameters,
            effects,
            risks,
            rollbackSteps);
    }

    private static bool IsValidObjectId(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 36)
            return false;
        if (!value.StartsWith("obj-", StringComparison.Ordinal))
            return false;
        return value.Skip(4).All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static bool IsPatternMatch(string objectId, string pattern)
    {
        // Simple prefix match for now. This could be extended to support glob patterns or regex if needed.
        return objectId.StartsWith(pattern, StringComparison.OrdinalIgnoreCase);
    }
}
