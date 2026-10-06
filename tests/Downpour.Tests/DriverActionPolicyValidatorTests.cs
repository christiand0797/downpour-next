using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public class DriverActionPolicyValidatorTests
{
    private readonly DriverActionCatalogSnapshot _catalog;
    private readonly IReadOnlyDictionary<string, FeatureSwitch> _featureSwitches;
    private readonly DriverActionPolicyValidator _validator;

    public DriverActionPolicyValidatorTests()
    {
        _catalog = DefaultDriverActionCatalog.GetCatalog();
        _featureSwitches = DefaultDriverActionCatalog.GetDefaultFeatureSwitches();
        _validator = new DriverActionPolicyValidator(_catalog, _featureSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);
    }

    [Fact]
    public void Validate_ValidDryRunRequest_WithDisabledFeatureSwitch_IsRejected()
    {
        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: true,
            UserConsentGiven: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.inf" },
                { "targetHardwareId", "PCI\\VEN_1234&DEV_5678" }
            });

        var result = _validator.Validate(request);

        Assert.False(result.Valid);
        Assert.Equal(ActionResultCodes.RejectedFeatureDisabled, result.RejectionReason);
        Assert.Single(result.PolicyViolations);
        Assert.Contains("disabled", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_NonDryRunRequest_WithoutConsent_IsRejected()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserConsentGiven: false,
            UserSid: "S-1-5-21-123456789-1234567890-1234567890-1234",
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.inf" },
                { "targetHardwareId", "PCI\\VEN_1234&DEV_5678" }
            });

        var result = validatorWithEnabled.Validate(request);

        Assert.False(result.Valid);
        Assert.Equal(ActionResultCodes.RejectedPermission, result.RejectionReason);
        Assert.Contains("consent", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_NonDryRunRequest_WithoutSid_IsRejected()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserConsentGiven: true,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.inf" },
                { "targetHardwareId", "PCI\\VEN_1234&DEV_5678" }
            });

        var result = validatorWithEnabled.Validate(request);

        Assert.False(result.Valid);
        Assert.Equal(ActionResultCodes.RejectedPermission, result.RejectionReason);
        Assert.Contains("SID", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_RequestWithInvalidActionKind_IsRejected()
    {
        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: "InvalidAction",
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: true,
            UserConsentGiven: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>());

        var result = _validator.Validate(request);

        Assert.False(result.Valid);
        Assert.Equal("action-kind-not-allowed", result.RejectionReason);
        Assert.Contains("catalog", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_RequestWithPolicyVersionMismatch_IsRejected()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: "0.0.0",
            DryRun: true,
            UserConsentGiven: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.inf" },
                { "targetHardwareId", "PCI\\VEN_1234&DEV_5678" }
            });

        var result = validatorWithEnabled.Validate(request);

        Assert.False(result.Valid);
        Assert.Equal("policy-version-mismatch", result.RejectionReason);
        Assert.Contains("mismatch", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_RequestWithMissingRequiredParameters_IsRejected()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: true,
            UserConsentGiven: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>()); // Missing required parameters

        var result = validatorWithEnabled.Validate(request);

        Assert.False(result.Valid);
        Assert.True(result.PolicyViolations.Count >= 2);
        Assert.Contains("infFilePath", result.PolicyViolations[0]);
    }

    [Fact]
    public void Validate_RequestWithInvalidInfFile_IsRejected()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.exe", // Not .inf
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: true,
            UserConsentGiven: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.exe" },
                { "targetHardwareId", "PCI\\VEN_1234&DEV_5678" }
            });

        var result = validatorWithEnabled.Validate(request);

        Assert.False(result.Valid);
        Assert.Contains("must have .inf extension", result.PolicyViolations);
    }

    [Fact]
    public void Validate_RequestWithMissingHardwareId_IsRejected()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "", // Empty
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: true,
            UserConsentGiven: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.inf" },
                { "targetHardwareId", "" }
            });

        var result = validatorWithEnabled.Validate(request);

        Assert.False(result.Valid);
        Assert.Contains("Target hardware ID is required", result.PolicyViolations);
    }

    [Fact]
    public void Validate_ValidRequestWithEnabledFeatureAndConsent_IsAccepted()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserConsentGiven: true,
            UserSid: "S-1-5-21-123456789-1234567890-1234567890-1234",
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.inf" },
                { "targetHardwareId", "PCI\\VEN_1234&DEV_5678" }
            });

        var result = validatorWithEnabled.Validate(request);

        Assert.True(result.Valid);
        Assert.Null(result.RejectionReason);
        Assert.Empty(result.PolicyViolations);
    }

    [Fact]
    public void GeneratePreview_ValidRequest_ReturnsPreviewWithEffectsAndRisks()
    {
        var enabledSwitches = new Dictionary<string, FeatureSwitch>(_featureSwitches)
        {
            [DriverActionKinds.InstallDriver] = _featureSwitches[DriverActionKinds.InstallDriver] with { Enabled = true }
        };
        var validatorWithEnabled = new DriverActionPolicyValidator(_catalog, enabledSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var request = new DriverPackageRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: DriverActionKinds.InstallDriver,
            DriverInfFile: @"C:\drivers\test.inf",
            TargetHardwareId: "PCI\\VEN_1234&DEV_5678",
            PolicyVersion: DefaultDriverActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserConsentGiven: false, // Preview should work without consent
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "infFilePath", @"C:\drivers\test.inf" },
                { "targetHardwareId", "PCI\\VEN_1234&DEV_5678" }
            });

        var preview = validatorWithEnabled.GeneratePreview(request);

        Assert.NotNull(preview);
        Assert.Equal(DriverActionKinds.InstallDriver, preview.ActionKind);
        Assert.Equal("Install Driver", preview.DisplayName);
        Assert.Equal(@"C:\drivers\test.inf", preview.DriverInfFile);
        Assert.NotEmpty(preview.ExpectedEffects);
        Assert.NotEmpty(preview.RiskItems);
        Assert.NotEmpty(preview.RollbackSteps);
    }
}
