namespace Downpour.Contracts;

public static class HostIsolationOperations
{
    public const string PreviewIsolate = "preview-isolate";
    public const string Isolate = "isolate";
    public const string PreviewRelease = "preview-release";
    public const string Release = "release";
    public const string GetStatus = "get-status";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        PreviewIsolate, Isolate,
        PreviewRelease, Release,
        GetStatus
    };
}

/// <summary>
/// Versioned request contract for Host Isolation actions (DN-008 Phase 5).
/// </summary>
public sealed record HostIsolationRequest(
    int SchemaVersion,
    Guid RequestId,
    string Operation,
    int DurationMinutes = 30,
    bool LockWorkstation = false,
    string? Reason = null,
    string? ConsentToken = null);

/// <summary>
/// Pre-execution preview of host isolation for operator review and itemized consent.
/// </summary>
public sealed record HostIsolationPreview(
    string Operation,
    int DurationMinutes,
    DateTimeOffset? ExpiresAtUtc,
    bool LockWorkstation,
    string? DenyReason,
    string? ConsentToken,
    IReadOnlyList<string> ExpectedEffects,
    IReadOnlyList<string> Risks,
    IReadOnlyList<string> RollbackSteps);

/// <summary>
/// Response payload for a host isolation action request.
/// </summary>
public sealed record HostIsolationResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string Message,
    bool ActionsEnabled,
    bool IsIsolated,
    DateTimeOffset? ActiveUntilUtc = null,
    IReadOnlyList<string>? RulesCreated = null,
    HostIsolationPreview? Preview = null);
