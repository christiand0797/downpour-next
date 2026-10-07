namespace Downpour.Contracts;

/// <summary>
/// Versioned action request contract. This represents a user-authorized request to perform a specific security action.
/// All requests must be explicitly consented to by the user through the UI before execution.
/// </summary>
public sealed record ActionRequest(
    int SchemaVersion,
    Guid RequestId,
    string ActionKind,
    string ObjectId,
    string PolicyVersion,
    bool DryRun,
    string? UserSid,
    DateTimeOffset RequestedAtUtc,
    IReadOnlyDictionary<string, string> Parameters,
    bool UserConsentGiven = false);

/// <summary>
/// Versioned action response contract. Contains the result of an action execution attempt,
/// including whether it was accepted, executed, and any audit information.
/// </summary>
public sealed record ActionResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string? OperationId,
    DateTimeOffset RespondedAtUtc,
    IReadOnlyDictionary<string, string> Details,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Action catalog entry defining the metadata and policy for a specific action kind.
/// Actions are explicitly allow-listed; only catalog entries may be executed.
/// </summary>
public sealed record ActionCatalogEntry(
    string ActionKind,
    string DisplayName,
    string Description,
    string Category,
    bool EnabledByDefault,
    bool RequiresElevation,
    int TimeoutSeconds,
    string RequiredPermission,
    IReadOnlyList<string> RequiredParameters,
    IReadOnlyList<string> AllowedObjectIdPatterns);

/// <summary>
/// Versioned action catalog snapshot. Contains all available actions and their policy constraints.
/// </summary>
public sealed record ActionCatalogSnapshot(
    int SchemaVersion,
    DateTimeOffset GeneratedAtUtc,
    IReadOnlyDictionary<string, ActionCatalogEntry> Actions,
    string CurrentPolicyVersion);

/// <summary>
/// Action policy validation result. Indicates whether a request satisfies all policy constraints.
/// </summary>
public sealed record ActionPolicyValidation(
    bool Valid,
    string? RejectionReason,
    IReadOnlyList<string> PolicyViolations,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Preview of what an action would do without executing it. Used for user consent dialogs.
/// </summary>
public sealed record ActionPreview(
    string ActionKind,
    string DisplayName,
    string ObjectId,
    IReadOnlyDictionary<string, string> Parameters,
    IReadOnlyList<string> ExpectedEffects,
    IReadOnlyList<string> Risks,
    IReadOnlyList<string> RollbackSteps);

/// <summary>
/// Feature switch configuration. Actions are disabled by default and must be explicitly enabled.
/// </summary>
public sealed record FeatureSwitch(
    string FeatureId,
    string DisplayName,
    string Description,
    bool Enabled,
    string RequiredPolicyVersion,
    DateTimeOffset? EnabledAtUtc);

/// <summary>
/// Supported action kinds. These are the only actions the broker will execute.
/// New action kinds must be added to the catalog before they can be requested.
/// </summary>
public static class ActionKinds
{
    public const string QuarantineFile = "QuarantineFile";
    public const string RestoreFile = "RestoreFile";
    public const string TerminateProcess = "TerminateProcess";
    public const string BlockRemoteIp = "BlockRemoteIp";
    public const string RemoveFirewallRule = "RemoveFirewallRule";
    public const string BlockUsbDevice = "BlockUsbDevice";
    public const string UnblockUsbDevice = "UnblockUsbDevice";
    public const string SetUsbStorage = "SetUsbStorage";
    // Future action kinds to be added in later phases:
    // public const string IsolateHost = "IsolateHost";
}

/// <summary>
/// Action result codes. These are the canonical result strings used in the journal and responses.
/// </summary>
public static class ActionResultCodes
{
    public const string Accepted = "accepted";
    public const string RejectedPolicy = "rejected-policy";
    public const string RejectedPermission = "rejected-permission";
    public const string RejectedFeatureDisabled = "rejected-feature-disabled";
    public const string RejectedDryRun = "rejected-dry-run";
    public const string RejectedNotImplemented = "rejected-not-implemented";
    public const string ExecutionStarted = "execution-started";
    public const string ExecutionCompleted = "execution-completed";
    public const string ExecutionFailed = "execution-failed";
    public const string ExecutionTimedOut = "execution-timed-out";
    public const string ExecutionCancelled = "execution-cancelled";
    public const string JournalWriteFailed = "journal-write-failed";
    public const string ObjectIdInvalid = "object-id-invalid";
    public const string ParameterInvalid = "parameter-invalid";
}
