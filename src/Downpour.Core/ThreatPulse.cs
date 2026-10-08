using Downpour.Contracts;

namespace Downpour.Core;

public sealed record ThreatPulseHour(DateTimeOffset StartUtc, int Count, int Serious);

public static class ThreatPulseStates
{
    public const string Learning = "learning";
    public const string Calm = "calm";
    public const string Elevated = "elevated";
    public const string Spike = "spike";
}

public sealed record ThreatPulseReading(
    IReadOnlyList<ThreatPulseHour> Last24Hours,
    string State,
    double Normal,
    double Threshold,
    int ThisHour,
    int ThisHourSerious,
    int BaselineHours,
    string Headline,
    string Detail);

/// <summary>
/// Threat Pulse (invented for Downpour Next): this PC's own normal rate of new findings per hour, learned from the
/// previous six days of local alerts, and whether the current hour is unusual. Uses a median and median absolute
/// deviation so a few noisy hours do not move the baseline; a spike needs both a statistical outlier and at least
/// <see cref="MinimumSpike"/> new findings. Nothing new is collected; it reads the alert store.
/// </summary>
public static class ThreatPulse
{
    public const int MinimumSpike = 4;
    public const int MinimumBaselineHours = 24;
    private static readonly TimeSpan BaselineSpan = TimeSpan.FromDays(6);

    /// <summary>From a snapshot: the service's whole-store hourly counts when present, otherwise the snapshot's alerts.</summary>
    public static ThreatPulseReading Compute(SecurityAlertSnapshot snapshot, DateTimeOffset now) =>
        snapshot.Hourly is { Count: > 0 } hourly ? Compute(hourly, now) : Compute(snapshot.Alerts, now);

    public static ThreatPulseReading Compute(IEnumerable<SecurityAlert> alerts, DateTimeOffset now) =>
        Compute(alerts
            .Select(alert => (Hour: Floor(alert.EventTimeUtc.ToUniversalTime()), Serious: alert.Severity is "CRITICAL" or "HIGH" ? 1 : 0))
            .GroupBy(x => x.Hour)
            .Select(group => new AlertHourCount(group.Key, group.Count(), group.Sum(x => x.Serious)))
            .ToArray(), now);

    public static ThreatPulseReading Compute(IReadOnlyList<AlertHourCount> hourly, DateTimeOffset now)
    {
        now = now.ToUniversalTime();
        var currentHour = Floor(now);
        var windowStart = currentHour - TimeSpan.FromHours(23);
        var baselineStart = windowStart - BaselineSpan;
        var counts = new Dictionary<DateTimeOffset, (int Count, int Serious)>();
        DateTimeOffset? oldest = null;
        foreach (var bucket in hourly)
        {
            var hour = Floor(bucket.HourUtc.ToUniversalTime());
            if (hour > currentHour || hour < baselineStart || bucket.Count <= 0) continue;
            if (oldest is null || hour < oldest) oldest = hour;
            counts.TryGetValue(hour, out var existing);
            counts[hour] = (existing.Count + bucket.Count, existing.Serious + Math.Min(bucket.Serious, bucket.Count));
        }

        var last24 = Enumerable.Range(0, 24)
            .Select(i => windowStart.AddHours(i))
            .Select(hour => counts.TryGetValue(hour, out var b) ? new ThreatPulseHour(hour, b.Count, b.Serious) : new ThreatPulseHour(hour, 0, 0))
            .ToArray();

        // Baseline: every hour from the oldest observation up to the start of today's window (quiet hours count as zero).
        var baselineFrom = oldest is { } first && first > baselineStart
            ? new DateTimeOffset(first.Year, first.Month, first.Day, first.Hour, 0, 0, TimeSpan.Zero)
            : baselineStart;
        var baseline = new List<double>();
        for (var hour = baselineFrom; hour < windowStart; hour = hour.AddHours(1))
            baseline.Add(counts.TryGetValue(hour, out var b) ? b.Count : 0);

        var now24 = last24[^1];
        if (baseline.Count < MinimumBaselineHours)
        {
            var hoursLeft = MinimumBaselineHours - baseline.Count;
            return new ThreatPulseReading(last24, ThreatPulseStates.Learning, 0, 0, now24.Count, now24.Serious, baseline.Count,
                "Learning this PC's normal",
                $"{now24.Count} new findings this hour. Threat Pulse needs about {hoursLeft} more hour{(hoursLeft == 1 ? "" : "s")} of history before it can tell what is unusual here.");
        }

        var median = Median(baseline);
        var spread = 1.4826 * Median(baseline.Select(value => Math.Abs(value - median)).ToList());
        var threshold = Math.Max(median + 3 * Math.Max(spread, 0.5), MinimumSpike);
        var elevatedAt = Math.Max(median + 2 * Math.Max(spread, 0.5), 2);
        var state = now24.Count >= threshold ? ThreatPulseStates.Spike
            : now24.Count >= elevatedAt || now24.Serious > 0 ? ThreatPulseStates.Elevated
            : ThreatPulseStates.Calm;
        var normalText = median < 1 ? "under 1 an hour" : $"about {median:0.#} an hour";
        var (headline, detail) = state switch
        {
            ThreatPulseStates.Spike => ($"Spike: {now24.Count} new findings this hour",
                $"About {(median < 1 ? now24.Count : now24.Count / median):0.#}× this PC's normal ({normalText}){(now24.Serious > 0 ? $", {now24.Serious} of them high or critical" : "")}. Review Triage to see what started it."),
            ThreatPulseStates.Elevated => ($"Elevated: {now24.Count} new findings this hour",
                now24.Serious > 0 ? $"{now24.Serious} high or critical this hour; normal here is {normalText}." : $"A little above normal ({normalText}); not unusual enough to call a spike."),
            _ => ($"Calm: {now24.Count} new findings this hour", $"Normal for this PC is {normalText}, learned from the last {baseline.Count} hours."),
        };
        return new ThreatPulseReading(last24, state, median, threshold, now24.Count, now24.Serious, baseline.Count, headline, detail);
    }

    private static DateTimeOffset Floor(DateTimeOffset time) => new(time.Year, time.Month, time.Day, time.Hour, 0, 0, TimeSpan.Zero);

    private static double Median(List<double> values)
    {
        if (values.Count == 0) return 0;
        values.Sort();
        var middle = values.Count / 2;
        return values.Count % 2 == 1 ? values[middle] : (values[middle - 1] + values[middle]) / 2;
    }
}
