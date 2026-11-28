namespace Downpour.Contracts;

/// <summary>Allow-listed scheduled-task operations. Only these strings are accepted by the service.</summary>
public static class ScheduledTaskActionOperations
{
    public const string PreviewEnable = "preview-enable-task";
    public const string Enable = "enable-task";
    public const string PreviewDisable = "preview-disable-task";
    public const string Disable = "disable-task";
    public const string PreviewDelete = "preview-delete-task";
    public const string Delete = "delete-task";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        PreviewEnable, Enable, PreviewDisable, Disable, PreviewDelete, Delete,
    };
}

/// <summary>What the operator is asking to change. Used by the desktop client to pick an operation pair.</summary>
public enum ScheduledTaskActionKind
{
    Enable,
    Disable,
    Delete,
}

/// <summary>Versioned request for a scheduled-task state change or removal.</summary>
public sealed record ScheduledTaskActionRequest(
    int SchemaVersion,
    Guid RequestId,
    string Operation,
    string? TaskPath = null,
    string? ConsentToken = null);

/// <summary>
/// Pre-execution preview for itemized consent. <see cref="ConsentToken"/> is single-use, short-lived and bound to
/// the operation and task path; it is the only way to execute.
/// </summary>
public sealed record ScheduledTaskActionPreview(
    string Operation,
    string TaskPath,
    bool? EnabledAfter,
    string? DenyReason,
    string? ConsentToken,
    DateTimeOffset? ExpiresAtUtc,
    IReadOnlyList<string> ExpectedEffects,
    IReadOnlyList<string> Risks);

public sealed record ScheduledTaskActionResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string Message,
    bool ActionsEnabled,
    string? TaskPath = null,
    bool? TaskEnabled = null,
    ScheduledTaskActionPreview? Preview = null);
