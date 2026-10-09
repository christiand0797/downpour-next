namespace Downpour.Contracts;

/// <summary>
/// One read-only platform posture check. <see cref="State"/> is one of <see cref="PostureStates"/>. Fix and SettingsUri say
/// how the person can correct a finding in Windows' own UI (Downpour does not change the setting itself).
/// </summary>
public sealed record PostureCheck(
    string Id,
    string Title,
    string State,
    string Severity,
    string Technique,
    string Detail,
    string? Category = null,
    string? Fix = null,
    string? SettingsUri = null);

public sealed record HardeningPostureSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    bool IsElevated,
    IReadOnlyList<PostureCheck> Checks,
    IReadOnlyList<string> Warnings);

public static class PostureStates
{
    public const string Pass = "Pass";
    public const string Finding = "Finding";
    public const string Unknown = "Unknown";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Pass, Finding, Unknown };
}
