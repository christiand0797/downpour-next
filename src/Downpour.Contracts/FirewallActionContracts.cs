namespace Downpour.Contracts;

public static class FirewallActionOperations
{
    public const string PreviewBlockIp = "preview-block-ip";
    public const string BlockIp = "block-ip";
    public const string PreviewRemoveRule = "preview-remove-rule";
    public const string RemoveRule = "remove-rule";
    public const string PreviewCleanupLegacy = "preview-cleanup-legacy";
    public const string CleanupLegacy = "cleanup-legacy";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        PreviewBlockIp, BlockIp,
        PreviewRemoveRule, RemoveRule,
        PreviewCleanupLegacy, CleanupLegacy
    };
}

/// <summary>
/// Versioned request contract for firewall actions (DN-008 Phase 3).
/// </summary>
public sealed record FirewallActionRequest(
    int SchemaVersion,
    Guid RequestId,
    string Operation,
    string? TargetIp = null,
    string? RuleName = null,
    int DurationMinutes = 1440, // Default 24 hours (0 = permanent)
    string? Reason = null,
    string? ConsentToken = null);

/// <summary>
/// Pre-execution preview of a firewall action for operator review and consent.
/// </summary>
public sealed record FirewallActionPreview(
    string Operation,
    string? TargetIp,
    string? RuleName,
    IReadOnlyList<string> RulesAffected,
    int DurationMinutes,
    string? DenyReason,
    string? ConsentToken,
    DateTimeOffset? ExpiresAtUtc,
    IReadOnlyList<string> ExpectedEffects,
    IReadOnlyList<string> Risks);

/// <summary>
/// Response payload for a firewall action request.
/// </summary>
public sealed record FirewallActionResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string Message,
    bool ActionsEnabled,
    IReadOnlyList<string>? RulesModified = null,
    FirewallActionPreview? Preview = null);
