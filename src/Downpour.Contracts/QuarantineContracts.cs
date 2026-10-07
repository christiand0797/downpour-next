namespace Downpour.Contracts;

/// <summary>Operations accepted by the quarantine action pipe (DN-008 phase 1). Everything else is rejected.</summary>
public static class QuarantineOperations
{
    public const string List = "list";
    public const string PreviewQuarantine = "previewQuarantine";
    public const string Quarantine = "quarantine";
    public const string PreviewRestore = "previewRestore";
    public const string Restore = "restore";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { List, PreviewQuarantine, Quarantine, PreviewRestore, Restore };
}

/// <summary>
/// One request per connection. Preview operations return a one-time consent token bound to the operation, the target, and
/// its SHA-256; the matching action must echo it within 60 seconds after the user confirms the preview.
/// </summary>
public sealed record QuarantineRequest(
    int SchemaVersion,
    Guid RequestId,
    string Operation,
    string? Path = null,
    string? ObjectId = null,
    string? RestorePath = null,
    string? ConsentToken = null);

public sealed record QuarantineItem(
    string ObjectId,
    string FileName,
    string OriginalPath,
    long Size,
    string Sha256,
    string Reason,
    DateTimeOffset QuarantinedAtUtc,
    DateTimeOffset? RestoredAtUtc,
    string? RestoredTo);

public sealed record QuarantinePreview(
    string TargetPath,
    long Size,
    string Sha256,
    string? DenyReason,
    string? ConsentToken,
    DateTimeOffset? ConsentExpiresUtc);

public sealed record QuarantineResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string Message,
    bool ActionsEnabled,
    QuarantinePreview? Preview = null,
    IReadOnlyList<QuarantineItem>? Items = null,
    IReadOnlyList<string>? RecoveryNotes = null);
