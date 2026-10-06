namespace Downpour.Contracts;

/// <summary>
/// Versioned driver package action request contract.
/// </summary>
public sealed record DriverPackageRequest(
    int SchemaVersion,
    Guid RequestId,
    string ActionKind,
    string DriverInfFile,
    string TargetHardwareId,
    string PolicyVersion,
    bool DryRun,
    bool UserConsentGiven,
    string? UserSid,
    DateTimeOffset RequestedAtUtc,
    IReadOnlyDictionary<string, string> Parameters);

/// <summary>
/// Versioned driver package action response contract.
/// </summary>
public sealed record DriverPackageResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string? OperationId,
    DateTimeOffset RespondedAtUtc,
    IReadOnlyDictionary<string, string> Details,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Driver package catalog entry defining metadata for a driver action kind.
/// </summary>
public sealed record DriverActionCatalogEntry(
    string ActionKind,
    string DisplayName,
    string Description,
    string Category,
    bool EnabledByDefault,
    bool RequiresElevation,
    int TimeoutSeconds,
    string RequiredPermission,
    IReadOnlyList<string> RequiredParameters);

/// <summary>
/// Versioned driver action catalog snapshot.
/// </summary>
public sealed record DriverActionCatalogSnapshot(
    int SchemaVersion,
    DateTimeOffset GeneratedAtUtc,
    IReadOnlyDictionary<string, DriverActionCatalogEntry> Actions,
    string CurrentPolicyVersion);

/// <summary>
/// Driver package entry from the Driver Store.
/// </summary>
public sealed record DriverPackageEntry(
    string InfFile,
    string OriginalInfFile,
    string DriverClass,
    string ProviderName,
    string DriverVersion,
    string Date,
    string HardwareId,
    bool IsSigned,
    string? SignerName,
    string? SignatureStatus);

/// <summary>
/// Driver package inventory snapshot.
/// </summary>
public sealed record DriverPackageInventorySnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    int PackageCount,
    IReadOnlyList<DriverPackageEntry> Packages,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Driver package preview information for user consent.
/// </summary>
public sealed record DriverPackagePreview(
    string ActionKind,
    string DisplayName,
    string DriverInfFile,
    string DriverVersion,
    string ProviderName,
    string HardwareId,
    bool IsSigned,
    string? SignerName,
    IReadOnlyDictionary<string, string> Parameters,
    IReadOnlyList<string> ExpectedEffects,
    IReadOnlyList<string> RiskItems,
    IReadOnlyList<string> RollbackSteps);

/// <summary>
/// Supported driver action kinds.
/// </summary>
public static class DriverActionKinds
{
    public const string InstallDriver = "InstallDriver";
    public const string UpdateDriver = "UpdateDriver";
    public const string UninstallDriver = "UninstallDriver";
    public const string ExportDriver = "ExportDriver";
    public const string RollbackDriver = "RollbackDriver";
}

/// <summary>
/// Driver action result codes.
/// </summary>
public static class DriverActionResultCodes
{
    public const string Accepted = "accepted";
    public const string RejectedPolicy = "rejected-policy";
    public const string RejectedPermission = "rejected-permission";
    public const string RejectedFeatureDisabled = "rejected-feature-disabled";
    public const string RejectedNotImplemented = "rejected-not-implemented";
    public const string ExecutionStarted = "execution-started";
    public const string ExecutionCompleted = "execution-completed";
    public const string ExecutionFailed = "execution-failed";
    public const string ExecutionTimedOut = "execution-timed-out";
    public const string ExecutionCancelled = "execution-cancelled";
    public const string JournalWriteFailed = "journal-write-failed";
    public const string InvalidInfFile = "invalid-inf-file";
    public const string SignatureVerificationFailed = "signature-verification-failed";
    public const string DriverNotFound = "driver-not-found";
    public const string HardwareIdMismatch = "hardware-id-mismatch";
    public const string ParameterInvalid = "parameter-invalid";
}
