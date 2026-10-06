namespace Downpour.Contracts;

/// <summary>
/// One autostart/persistence item. <see cref="Value"/> is the live command or path; it is shown locally and never
/// persisted (the baseline stores only a SHA-256 of it). <see cref="Change"/> is one of <see cref="PersistenceChanges"/>.
/// </summary>
public sealed record PersistenceEntry(
    string Category,
    string Location,
    string Name,
    string Value,
    string Technique,
    string Change,
    DateTimeOffset? ChangedAtUtc,
    IReadOnlyList<string> Indicators);

public sealed record PersistenceFinding(string Severity, string Technique, string Category, string Summary, string Indicator);

public sealed record PersistenceSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    DateTimeOffset? BaselineCreatedAtUtc,
    bool IsFirstBaseline,
    IReadOnlyList<PersistenceEntry> Entries,
    IReadOnlyList<PersistenceFinding> Findings,
    IReadOnlyList<string> SourceStatus,
    IReadOnlyList<string> Warnings);

public static class PersistenceChanges
{
    /// <summary>Present when the baseline was created (trust on first use) and unchanged since.</summary>
    public const string Baseline = "Baseline";
    public const string New = "New";
    public const string Modified = "Modified";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Baseline, New, Modified };
}

public static class PersistenceCategories
{
    public const string RegistryRun = "Registry autostart";
    public const string Winlogon = "Winlogon";
    public const string StartupFolder = "Startup folder";
    public const string ScheduledTask = "Scheduled task";
    public const string WmiSubscription = "WMI subscription";
    public const string DllShadow = "DLL shadow";
    public const string DriverFile = "Driver file";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
        { RegistryRun, Winlogon, StartupFolder, ScheduledTask, WmiSubscription, DllShadow, DriverFile };
}
