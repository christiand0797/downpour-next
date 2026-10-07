namespace Downpour.Contracts;

/// <summary>
/// Configuration for daily screen time limits and bedtime restrictions.
/// </summary>
public sealed record ScreenTimeSchedule(
    bool Enabled,
    int WeekdayLimitMinutes,
    int WeekendLimitMinutes,
    string BedtimeStart,
    string BedtimeEnd);

/// <summary>
/// Configuration for web content category filtering and DNS blocklists.
/// </summary>
public sealed record WebFilterPolicy(
    bool Enabled,
    bool BlockAdultContent,
    bool BlockGambling,
    bool BlockViolence,
    bool BlockWeapons,
    bool BlockDrugs,
    IReadOnlyList<string> CustomBlockedDomains,
    bool SafeSearchEnforced);

/// <summary>
/// Policy restricting execution of sensitive or unapproved applications.
/// </summary>
public sealed record AppRestrictionPolicy(
    bool Enabled,
    IReadOnlyList<string> BlockedExecutableNames,
    string MonitoredProfileUsername);

/// <summary>
/// Master configuration bundle for parental controls and family safety.
/// </summary>
public sealed record ParentalControlsConfig(
    bool Enabled,
    string ProfileName,
    ScreenTimeSchedule ScreenTime,
    WebFilterPolicy WebFilter,
    AppRestrictionPolicy AppRestrictions);

/// <summary>
/// Real-time evaluation of screen time limits and bedtime curfew.
/// </summary>
public sealed record ScreenTimeStatus(
    bool IsWithinCurfew,
    string CurfewMessage,
    int TodayUsageMinutes,
    int TodayLimitMinutes,
    int RemainingMinutes,
    bool IsLimitExceeded,
    double WarningPercent,
    bool HasUsageMeasurement = true);

/// <summary>
/// Assessment of Windows hosts file DNS filtering posture.
/// </summary>
public sealed record HostsFileFilterPosture(
    string HostsFilePath,
    bool IsAccessible,
    bool HasDownpourFilterMarker,
    int ActiveBlockedDomainsCount,
    DateTimeOffset? LastUpdatedUtc);

/// <summary>
/// Recorded activity or policy enforcement event.
/// </summary>
public sealed record ParentalActivityLogEntry(
    DateTimeOffset TimestampUtc,
    string Category,
    string Severity,
    string Summary);

/// <summary>
/// Complete point-in-time posture snapshot for parental controls.
/// </summary>
public sealed record ParentalPostureSnapshot(
    DateTimeOffset CapturedAtUtc,
    ParentalControlsConfig Config,
    ScreenTimeStatus ScreenTime,
    HostsFileFilterPosture HostsPosture,
    IReadOnlyList<string> RestrictedAppsRunning,
    IReadOnlyList<ParentalActivityLogEntry> ActivityLog);
