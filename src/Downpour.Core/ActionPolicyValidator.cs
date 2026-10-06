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
