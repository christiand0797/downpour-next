using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public class ActionPolicyValidatorTests
{
    private readonly ActionCatalogSnapshot _catalog;
    private readonly IReadOnlyDictionary<string, FeatureSwitch> _featureSwitches;
    private readonly ActionPolicyValidator _validator;

    public ActionPolicyValidatorTests()
    {
        _catalog = DefaultActionCatalog.GetCatalog();
        _featureSwitches = DefaultActionCatalog.GetDefaultFeatureSwitches();
        // Enable features for testing
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = _featureSwitches[ActionKinds.QuarantineFile] with { Enabled = true },
            [ActionKinds.RestoreFile] = _featureSwitches[ActionKinds.RestoreFile] with { Enabled = true }
        };
        _validator = new ActionPolicyValidator(_catalog, enabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);
    }

    [Fact]
    public void Validate_WithValidRequest_ReturnsValid()
    {
        // Arrange
        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: "S-1-5-21-123456789-1234567890-1234567890-1234",
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            },
            UserConsentGiven: true);

        // Act
        var result = _validator.Validate(request);

        // Assert
        Assert.True(result.Valid);
        Assert.Null(result.RejectionReason);
        Assert.Empty(result.PolicyViolations);
    }

    [Fact]
    public void Validate_WithUnsupportedSchemaVersion_ReturnsInvalid()
    {
        // Arrange
        var request = new ActionRequest(
            SchemaVersion: 999,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>());

        // Act
        var result = _validator.Validate(request);

        // Assert
        Assert.False(result.Valid);
        Assert.Equal("schema-version-unsupported", result.RejectionReason);
        Assert.Contains("Unsupported schema version", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_WithUnknownActionKind_ReturnsInvalid()
    {
        // Arrange
        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: "UnknownAction",
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>());

        // Act
        var result = _validator.Validate(request);

        // Assert
        Assert.False(result.Valid);
        Assert.Equal("action-kind-not-allowed", result.RejectionReason);
        Assert.Contains("not in the allow-list catalog", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_WithFeatureDisabled_ReturnsInvalid()
    {
        // Arrange
        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            });

        // Use a validator with the feature explicitly disabled
        var disabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = _featureSwitches[ActionKinds.QuarantineFile] with { Enabled = false }
        };
        var validatorWithDisabledFeature = new ActionPolicyValidator(_catalog, disabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);

        // Act
        var result = validatorWithDisabledFeature.Validate(request);

        // Assert
        Assert.False(result.Valid);
        Assert.Equal(ActionResultCodes.RejectedFeatureDisabled, result.RejectionReason);
        Assert.Contains("disabled by feature switch", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_WithMissingConsent_ReturnsPermissionRejected()
    {
        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: "S-1-5-21-123456789-1234567890-1234567890-1234",
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            });

        var result = _validator.Validate(request);

        Assert.False(result.Valid);
        Assert.Equal(ActionResultCodes.RejectedPermission, result.RejectionReason);
        Assert.Contains(result.PolicyViolations, violation => violation.Contains("Explicit user consent"));
    }

    [Fact]
    public void Validate_WithConsentButNoOperatorSid_ReturnsPermissionRejected()
    {
        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            },
            UserConsentGiven: true);

        var result = _validator.Validate(request);

        Assert.False(result.Valid);
        Assert.Equal(ActionResultCodes.RejectedPermission, result.RejectionReason);
        Assert.Contains(result.PolicyViolations, violation => violation.Contains("user SID"));
    }

    [Fact]
    public void Validate_WithPolicyVersionMismatch_ReturnsInvalid()
    {
        // Arrange
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = _featureSwitches[ActionKinds.QuarantineFile] with { Enabled = true }
        };
        var validatorWithEnabledFeature = new ActionPolicyValidator(_catalog, enabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: "0.0.0", // Wrong version
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            });

        // Act
        var result = validatorWithEnabledFeature.Validate(request);

        // Assert
        Assert.False(result.Valid);
        Assert.Equal("policy-version-mismatch", result.RejectionReason);
        Assert.Contains("Policy version mismatch", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_WithMissingRequiredParameter_ReturnsInvalid()
    {
        // Arrange
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = _featureSwitches[ActionKinds.QuarantineFile] with { Enabled = true }
        };
        var validatorWithEnabledFeature = new ActionPolicyValidator(_catalog, enabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" }
                // Missing expectedHash
            });

        // Act
        var result = validatorWithEnabledFeature.Validate(request);

        // Assert
        Assert.False(result.Valid);
        Assert.Contains("Missing required parameter", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_WithInvalidObjectId_ReturnsInvalid()
    {
        // Arrange
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = _featureSwitches[ActionKinds.QuarantineFile] with { Enabled = true }
        };
        var validatorWithEnabledFeature = new ActionPolicyValidator(_catalog, enabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "invalid-id", // Wrong format
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            },
            UserConsentGiven: true);

        // Act
        var result = validatorWithEnabledFeature.Validate(request);

        // Assert
        Assert.False(result.Valid);
        Assert.Contains("Object ID must use the 'obj-'", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_WithDryRun_ReturnsValidWithWarning()
    {
        // Arrange
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = _featureSwitches[ActionKinds.QuarantineFile] with { Enabled = true }
        };
        var validatorWithEnabledFeature = new ActionPolicyValidator(_catalog, enabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: true,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            },
            UserConsentGiven: true);

        // Act
        var result = validatorWithEnabledFeature.Validate(request);

        // Assert
        Assert.True(result.Valid);
        Assert.Contains(result.Warnings, w => w.Contains("dry-run", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void GeneratePreview_WithValidRequest_ReturnsPreview()
    {
        // Arrange
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches, StringComparer.OrdinalIgnoreCase)
        {
            [ActionKinds.QuarantineFile] = _featureSwitches[ActionKinds.QuarantineFile] with { Enabled = true }
        };
        var validatorWithEnabledFeature = new ActionPolicyValidator(_catalog, enabledSwitches, DefaultActionCatalog.CurrentPolicyVersion);

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" },
                { "expectedHash", "abc123" }
            });

        // Act
        var preview = validatorWithEnabledFeature.GeneratePreview(request);

        // Assert
        Assert.Equal(ActionKinds.QuarantineFile, preview.ActionKind);
        Assert.Equal("Quarantine File", preview.DisplayName);
        Assert.Equal("obj-0123456789abcdef0123456789abcdef", preview.ObjectId);
        Assert.NotEmpty(preview.ExpectedEffects);
        Assert.NotEmpty(preview.Risks);
        Assert.NotEmpty(preview.RollbackSteps);
    }

    [Fact]
    public void GeneratePreview_WithInvalidRequest_Throws()
    {
        // Arrange
        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "invalid-id",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>());

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => _validator.GeneratePreview(request));
    }
}
