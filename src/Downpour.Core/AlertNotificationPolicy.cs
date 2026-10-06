using Downpour.Contracts;

namespace Downpour.Core;

public sealed record AlertNotification(string Title, string Body, string HighestSeverity, int Count);

/// <summary>
/// Decides which alerts raise a desktop notification and which sound to play. Ports v29 behavior: toasts for new
/// detections and the opt-in _play_alarm (downpour_v29_titanium.py line 36669) with its threshold and beep patterns.
/// </summary>
public sealed class AlertNotificationPolicy
{
    public const int MaximumIndividualNotifications = 3;
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private bool _baselined;

    /// <summary>
    /// Returns notifications for alerts not seen before. The first call only records a baseline, so starting the
    /// app does not replay every stored alert. Only open, unverified-or-verified HIGH/CRITICAL alerts notify.
    /// </summary>
    public IReadOnlyList<AlertNotification> Next(IReadOnlyList<SecurityAlert> alerts)
    {
        var fresh = alerts.Where(alert => _seen.Add(alert.AlertId)).ToArray();
        if (!_baselined)
        {
            _baselined = true;
            return [];
        }
        if (_seen.Count > 50_000) _seen.Clear();

        var notable = fresh
            .Where(alert => alert.State == "Open" && alert.Severity is "CRITICAL" or "HIGH")
            .OrderBy(alert => alert.Severity == "CRITICAL" ? 0 : 1)
            .ToArray();
        if (notable.Length == 0) return [];
        if (notable.Length <= MaximumIndividualNotifications)
            return notable.Select(alert => new AlertNotification($"{alert.Severity}: {Source(alert)}", alert.Title, alert.Severity, 1)).ToArray();

        var highest = notable[0].Severity;
        var critical = notable.Count(alert => alert.Severity == "CRITICAL");
        return
        [
            new AlertNotification($"{notable.Length} new alerts",
                $"{critical} critical, {notable.Length - critical} high. Latest: {notable[0].Title}", highest, notable.Length)
        ];
    }

    /// <summary>v29 _play_alarm threshold: CRITICAL only by default; optionally HIGH as well.</summary>
    public static bool ShouldSound(string severity, bool includeHigh) =>
        severity == "CRITICAL" || (includeHigh && severity == "HIGH");

    /// <summary>v29 winsound.Beep patterns as (frequency Hz, duration ms).</summary>
    public static IReadOnlyList<(int Frequency, int Duration)> BeepPattern(string severity) => severity switch
    {
        "CRITICAL" => [(1000, 300), (750, 200), (1000, 300), (750, 200), (1000, 300), (750, 200)],
        "HIGH" => [(880, 500)],
        _ => [(660, 200)]
    };

    private static string Source(SecurityAlert alert) => alert.LogName switch
    {
        SecurityFindingCatalog.Hardening => "Hardening",
        SecurityFindingCatalog.Firewall => "Firewall",
        SecurityFindingCatalog.Persistence => "Persistence",
        _ when alert.LogName.StartsWith("Downpour/", StringComparison.Ordinal) => alert.LogName["Downpour/".Length..],
        _ => alert.LogName
    };
}
