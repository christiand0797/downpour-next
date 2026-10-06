using Downpour.Contracts;
using System.Collections.Generic;

namespace Downpour.Core;

/// <summary>
/// Validates driver package action requests against policy constraints.
/// This enforces default-deny: no driver action executes unless explicitly authorized by policy and user consent.
/// </summary>
public sealed class DriverActionPolicyValidator
{
    private readonly DriverActionCatalogSnapshot _catalog;
    private readonly IReadOnlyDictionary<string, FeatureSwitch> _featureSwitches;
    private readonly string _currentPolicyVersion;

    public DriverActionPolicyValidator(
        DriverActionCatalogSnapshot catalog,
        IReadOnlyDictionary<string, FeatureSwitch> featureSwitches,
        string currentPolicyVersion)
    {
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _featureSwitches = featureSwitches ?? throw new ArgumentNullException(nameof(featureSwitches));
        _currentPolicyVersion = currentPolicyVersion ?? throw new ArgumentNullException(nameof(currentPolicyVersion));
    }

    /// <summary>
    /// Validates a driver action request against all policy constraints.
    /// </summary>
    public ActionPolicyValidation Validate(DriverPackageRequest request)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var policyViolations = new List<string>();
        var warnings = new List<string>();
        var permissionRejected = false;

        // Check schema version
        if (request.SchemaVersion != 1)
        {
            policyViolations.Add($"Unsupported schema version {request.SchemaVersion}; expected 1.");
            return new ActionPolicyValidation(false, "schema-version-unsupported", policyViolations, warnings);
        }

        // Check if action kind exists in catalog
        if (!_catalog.Actions.TryGetValue(request.ActionKind, out var catalogEntry))
        {
            policyViolations.Add($"Action kind '{request.ActionKind}' is not in the allow-list catalog.");
            return new ActionPolicyValidation(false, "action-kind-not-allowed", policyViolations, warnings);
        }

        // Check feature switch (default-deny)
        if (!_featureSwitches.TryGetValue(request.ActionKind, out var featureSwitch) || !featureSwitch.Enabled)
        {
            policyViolations.Add($"Action kind '{request.ActionKind}' is disabled by feature switch.");
            return new ActionPolicyValidation(false, ActionResultCodes.RejectedFeatureDisabled, policyViolations, warnings);
        }

        // Check policy version
        if (request.PolicyVersion != _currentPolicyVersion)
        {
            policyViolations.Add($"Policy version mismatch: request '{request.PolicyVersion}' vs current '{_currentPolicyVersion}'.");
            return new ActionPolicyValidation(false, "policy-version-mismatch", policyViolations, warnings);
        }

        // Check required parameters
        foreach (var requiredParam in catalogEntry.RequiredParameters)
        {
            if (!request.Parameters.ContainsKey(requiredParam))
            {
                policyViolations.Add($"Missing required parameter: {requiredParam}.");
            }
        }

        // Validate INF file format
        if (!IsValidInfFile(request.DriverInfFile))
        {
            policyViolations.Add("must have .inf extension");
        }

        // Validate hardware ID format (basic validation - actual matching happens during execution)
        if (string.IsNullOrWhiteSpace(request.TargetHardwareId))
        {
            policyViolations.Add("Target hardware ID is required");
        }

        // Non-dry-run requests need an explicit consent signal and operator identity
        if (!request.DryRun && !request.UserConsentGiven)
        {
            policyViolations.Add("Explicit user consent is required for a non-dry-run driver action request.");
            permissionRejected = true;
        }
        if (!request.DryRun && string.IsNullOrWhiteSpace(request.UserSid))
        {
            policyViolations.Add("An operator user SID is required for a consented driver action request.");
            permissionRejected = true;
        }

        // Preview generation calls validation with consent deferred
        if (request.DryRun)
        {
            warnings.Add("Request is a dry-run; no system changes will be applied.");
        }

        if (policyViolations.Count > 0)
        {
            return new ActionPolicyValidation(false,
                permissionRejected ? ActionResultCodes.RejectedPermission : ActionResultCodes.RejectedPolicy,
                policyViolations,
                warnings);
        }

        return new ActionPolicyValidation(true, null, policyViolations, warnings);
    }

    /// <summary>
    /// Generates a preview of what the driver action would do, for user consent dialogs.
    /// Preview validation accepts requests without consent so the user can inspect before consenting.
    /// </summary>
    public DriverPackagePreview GeneratePreview(DriverPackageRequest request)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        // For preview, treat as dry-run to allow validation without consent
        var previewRequest = request with { DryRun = true };
        var validation = Validate(previewRequest);
        if (!validation.Valid)
        {
            throw new InvalidOperationException($"Cannot generate preview for invalid request: {validation.RejectionReason}");
        }

        var catalogEntry = _catalog.Actions[request.ActionKind];

        var effects = new List<string>();
        var riskItems = new List<string>();
        var rollbackSteps = new List<string>();

        switch (request.ActionKind)
        {
            case DriverActionKinds.InstallDriver:
                effects.Add($"Install driver from '{request.DriverInfFile}' to the Driver Store");
                effects.Add("Verify cryptographic signature before installation");
                effects.Add("Record operation in the audit journal");
                riskItems.Add("If signature verification fails, installation will be blocked");
                riskItems.Add("If the driver is incompatible, system may become unstable");
                riskItems.Add("Installation may require a system reboot");
                rollbackSteps.Add("Uninstall the driver via Device Manager or rollback procedure");
                rollbackSteps.Add("System may need to boot into Safe Mode to complete rollback");
                break;

            case DriverActionKinds.UpdateDriver:
                effects.Add($"Update existing driver with '{request.DriverInfFile}'");
                effects.Add("Verify cryptographic signature before update");
                effects.Add("Record operation in the audit journal");
                riskItems.Add("If signature verification fails, update will be blocked");
                riskItems.Add("If the new driver is incompatible, system may become unstable");
                riskItems.Add("Update may require a system reboot");
                rollbackSteps.Add("Rollback to the previous driver version");
                rollbackSteps.Add("System may need to boot into Safe Mode to complete rollback");
                break;

            case DriverActionKinds.UninstallDriver:
                effects.Add($"Uninstall driver matching '{request.TargetHardwareId}'");
                effects.Add("Record operation in the audit journal");
                riskItems.Add("If the driver is in use, uninstall may fail or require reboot");
                riskItems.Add("System may become unstable if critical driver is removed");
                rollbackSteps.Add("Reinstall the driver from the original INF file");
                rollbackSteps.Add("System may need to boot into Safe Mode to complete rollback");
                break;

            case DriverActionKinds.ExportDriver:
                effects.Add($"Export driver package to '{request.Parameters.GetValueOrDefault("exportPath", "")}'");
                effects.Add("Record operation in the audit journal");
                riskItems.Add("Export does not modify the system");
                rollbackSteps.Add("Delete the exported file if no longer needed");
                break;

            case DriverActionKinds.RollbackDriver:
                effects.Add($"Rollback driver to previously installed version");
                effects.Add("Verify cryptographic signature before rollback");
                effects.Add("Record operation in the audit journal");
                riskItems.Add("If rollback package is not available, rollback will fail");
                riskItems.Add("System may become unstable if rollback fails");
                rollbackSteps.Add("Reinstall the current driver version if rollback fails");
                break;

            default:
                effects.Add($"Execute action '{request.ActionKind}' on '{request.DriverInfFile}'");
                riskItems.Add("Action-specific risks not yet documented");
                rollbackSteps.Add("Refer to action-specific rollback procedure");
                break;
        }

        return new DriverPackagePreview(
            request.ActionKind,
            catalogEntry.DisplayName,
            request.DriverInfFile,
            "", // Version will be parsed from INF during execution
            "", // Provider will be parsed from INF during execution
            request.TargetHardwareId,
            false, // Signature status will be verified during execution
            null, // Signer name will be extracted during execution
            request.Parameters,
            effects,
            riskItems,
            rollbackSteps);
    }

    private static bool IsValidInfFile(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        if (value.Length > 260)
            return false;
        return value.EndsWith(".inf", StringComparison.OrdinalIgnoreCase);
    }
}
