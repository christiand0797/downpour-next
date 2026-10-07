namespace Downpour.Contracts;

/// <summary>
/// Operations supported by the process termination action pipe (DN-008 phase 2).
/// All operations are default-deny and require explicit operator review.
/// </summary>
public static class ProcessTerminationOperations
{
    public const string Preview = "preview";
    public const string Terminate = "terminate";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Preview,
        Terminate
    };
}

/// <summary>
/// Versioned process termination request. Every non-preview request requires a one-time consent token
/// bound to the process ID, start time, and image path, minted by the service during preview.
/// </summary>
public sealed record ProcessTerminationRequest(
    int SchemaVersion,
    Guid RequestId,
    string Operation,
    int ProcessId,
    DateTimeOffset StartTimeUtc,
    string? AlertId = null,
    string? ConsentToken = null);

/// <summary>
/// Process termination preview presented to the operator prior to consent.
/// Details the target process, start time verification, risks, and one-time consent token.
/// </summary>
public sealed record ProcessTerminationPreview(
    int ProcessId,
    string ProcessName,
    string ImagePath,
    DateTimeOffset StartTimeUtc,
    string? AlertId,
    string? DenyReason,
    string? ConsentToken,
    DateTimeOffset? ConsentExpiresUtc,
    IReadOnlyList<string> ExpectedEffects,
    IReadOnlyList<string> Risks);

/// <summary>
/// Response from the process termination action endpoint.
/// </summary>
public sealed record ProcessTerminationResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string Message,
    bool ActionsEnabled,
    ProcessTerminationPreview? Preview = null);
