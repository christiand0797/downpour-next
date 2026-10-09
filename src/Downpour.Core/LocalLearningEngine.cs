using Downpour.Contracts;

namespace Downpour.Core;

public sealed record LocalMetricAggregate(int Count, double Mean);
public sealed record LocalLearningBucket(DateTimeOffset StartUtc, IReadOnlyList<LocalMetricAggregate> Metrics);
public sealed record LocalLearningHistory(int SchemaVersion, DateTimeOffset? LastObservationUtc, IReadOnlyList<LocalLearningBucket> Buckets);
public sealed record LocalLearningFrame(DateTimeOffset ObservedUtc, double? Cpu, double? Memory, double? Connections, double? Processes);

/// <summary>
/// Bounded per-PC robust baselines over observed five-minute averages. Missing time is never filled with synthetic zeroes.
/// The current bucket is excluded when judging a reading, so it cannot train away its own anomaly. No response actions.
/// </summary>
public static class LocalLearningEngine
{
    public const int MaximumBuckets = 2016; // seven days
    public const int MinimumBaselineBuckets = 24; // two hours actually observed, not elapsed wall time
    public static readonly TimeSpan BucketWidth = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan Retention = TimeSpan.FromDays(7);
    public static readonly IReadOnlyList<string> MetricIds = Array.AsReadOnly(new[] { "cpu", "memory", "connections", "processes" });
    private static readonly double[] MaximumValues = [100, 100, 1_000_000, 100_000];
    private static readonly double[] MinimumDeviations = [10, 5, 15, 25];
    public static LocalLearningHistory Empty => new(1, null, []);

    public static LocalLearningFrame FromSnapshot(SystemHealthSnapshot snapshot) => new(snapshot.CapturedAtUtc,
        snapshot.CpuPercent, snapshot.MemoryTotalBytes > 0 && snapshot.MemoryAvailableBytes <= snapshot.MemoryTotalBytes
            ? 100d * (snapshot.MemoryTotalBytes - snapshot.MemoryAvailableBytes) / snapshot.MemoryTotalBytes : null,
        snapshot.ActiveTcpConnections, snapshot.Warnings.Any(w => w.Contains("Process inventory", StringComparison.OrdinalIgnoreCase))
            ? null : snapshot.ProcessCount);

    public static bool IsValidHistory(LocalLearningHistory? history, DateTimeOffset now)
    {
        if (history is not { SchemaVersion: 1, Buckets: { Count: <= MaximumBuckets } }) return false;
        if (history.Buckets.Count == 0) return history.LastObservationUtc is null;
        if (history.LastObservationUtc is not { } last || last > now.AddMinutes(1)) return false;
        DateTimeOffset? previous = null;
        foreach (var bucket in history.Buckets)
        {
            if (bucket is null || bucket.StartUtc.Offset != TimeSpan.Zero || bucket.StartUtc != Floor(bucket.StartUtc)
                || bucket.StartUtc > last || (previous is { } p && bucket.StartUtc <= p)
                || bucket.Metrics is not { Count: 4 }) return false;
            if (bucket.Metrics.All(m => m is not null && m.Count == 0)) return false;
            for (var i = 0; i < 4; i++)
            {
                var metric = bucket.Metrics[i];
                if (metric is null || metric.Count is < 0 or > 5 || !Finite(metric.Mean, i)
                    || (metric.Count == 0 && metric.Mean != 0)) return false;
            }
            previous = bucket.StartUtc;
        }
        return last < history.Buckets[^1].StartUtc + BucketWidth;
    }

    public static bool IsValidFrame(LocalLearningFrame? frame, DateTimeOffset now) => frame is not null
        && frame.ObservedUtc >= now.AddMinutes(-2) && frame.ObservedUtc <= now.AddSeconds(30)
        && Values(frame).Select((v, i) => v is null || Finite(v.Value, i)).All(valid => valid);

    public static LocalLearningHistory Observe(LocalLearningHistory history, LocalLearningFrame frame, DateTimeOffset now)
    {
        if (!IsValidHistory(history, now) || !IsValidFrame(frame, now)) throw new InvalidDataException("Invalid local learning input.");
        var retained = history.Buckets.Where(b => b.StartUtc >= Floor(now - Retention)).ToList();
        if (history.LastObservationUtc is { } last && Minute(frame.ObservedUtc) <= Minute(last))
            return history; // restart, duplicate read, or backward clock: never double-count the minute
        var values = Values(frame);
        if (values.All(v => v is null)) return history;
        var start = Floor(frame.ObservedUtc);
        var bucket = retained.LastOrDefault();
        if (bucket is null || bucket.StartUtc != start)
        {
            bucket = new(start, Enumerable.Range(0, 4).Select(_ => new LocalMetricAggregate(0, 0)).ToArray());
            retained.Add(bucket);
        }
        var aggregates = bucket.Metrics.Select((m, i) => values[i] is { } value
            ? new LocalMetricAggregate(m.Count + 1, m.Mean + (value - m.Mean) / (m.Count + 1)) : m).ToArray();
        retained[^1] = bucket with { Metrics = aggregates };
        return new(1, frame.ObservedUtc.ToUniversalTime(), retained.TakeLast(MaximumBuckets).ToArray());
    }

    public static LocalLearningHistory Prune(LocalLearningHistory history, DateTimeOffset now)
    {
        var retained = history.Buckets.Where(b => b.StartUtc >= Floor(now - Retention)).ToArray();
        return retained.Length == history.Buckets.Count ? history : retained.Length == 0 ? Empty
            : history with { Buckets = retained };
    }

    public static LocalLearningSnapshot Assess(LocalLearningHistory history, LocalLearningFrame? frame,
        SecurityAlertSnapshot? alerts, DateTimeOffset now, bool enabled = true, IReadOnlyList<string>? storageWarnings = null)
    {
        var warnings = new List<string>(storageWarnings ?? []);
        var validHistory = IsValidHistory(history, now);
        if (!validHistory) { history = Empty; warnings.Add("Saved learning history is invalid; no baseline was trusted."); }
        var available = enabled && IsValidFrame(frame, now);
        var values = available ? Values(frame!) : new double?[4];
        if (enabled && !available) warnings.Add("Current aggregate telemetry is unavailable or stale; no observation was learned.");
        var historyBuckets = history.Buckets.Where(b => b.StartUtc >= Floor(now - Retention) && b.StartUtc < Floor(now)).ToArray();
        var metrics = new List<LocalMetricReading>();
        for (var i = 0; i < 4; i++)
        {
            var samples = historyBuckets.Where(b => b.Metrics[i].Count > 0).Select(b => b.Metrics[i].Mean).ToArray();
            double? normal = null, threshold = null;
            if (samples.Length >= MinimumBaselineBuckets)
            {
                normal = Median(samples);
                var mad = Median(samples.Select(x => Math.Abs(x - normal.Value)).ToArray());
                threshold = Math.Min(MaximumValues[i], normal.Value + Math.Max(MinimumDeviations[i], 4 * 1.4826 * mad));
            }
            var state = !enabled ? "paused" : values[i] is null ? "unavailable" : normal is null ? "learning"
                : values[i] > threshold ? "unusual" : "typical";
            metrics.Add(new(MetricIds[i], values[i], normal, threshold, samples.Length, state));
        }

        var recommendations = new List<LocalRecommendation>();
        var unusual = metrics.Where(m => m.State == "unusual").Select(m => m.Id).ToHashSet();
        var freshAlerts = enabled && alerts is { Alerts.Count: <= 512, Warnings.Count: <= 32 }
            && alerts.Alerts.All(a => a is not null) && alerts.CapturedAtUtc >= now.AddMinutes(-2)
            && alerts.CapturedAtUtc <= now.AddMinutes(1);
        var urgent = freshAlerts ? alerts!.Alerts.Where(a => a.State == "Open" && a.Severity is "HIGH" or "CRITICAL"
            && a.LastSeenUtc >= now.AddMinutes(-15) && a.LastSeenUtc <= now.AddMinutes(1)).ToArray() : [];
        if (enabled && !freshAlerts) warnings.Add("Alert context is unavailable or stale; correlation is incomplete.");
        if (urgent.Length > 0)
            recommendations.Add(new("urgent", "Review recent urgent findings",
                $"{urgent.Length} recent open HIGH/CRITICAL finding(s) in the returned alert window. Review their evidence and source confidence.", "threats"));
        if (unusual.Contains("connections") && urgent.Length > 0)
            recommendations.Add(new("network-context", "Unusual connections coincide with urgent findings",
                "TCP connections exceed this PC's observed baseline while recent urgent findings are open. This is temporal co-occurrence, not proof that those processes caused the findings. Review Network and Triage.", "network"));
        if (unusual.Contains("cpu") || unusual.Contains("memory"))
            recommendations.Add(new("resources", "Inspect unusual resource pressure",
                "CPU or memory exceeds its local robust baseline. Games, updates and scans can explain this; inspect live process usage before taking action.", "processes"));
        if (unusual.Contains("connections") && urgent.Length == 0)
            recommendations.Add(new("connections", "Review the increased connection count",
                "More TCP connections than this PC's observed baseline. Downloads and browser tabs may explain the increase; the count alone is not a threat verdict.", "network"));
        if (unusual.Contains("processes"))
            recommendations.Add(new("processes", "Review the increased process count",
                "More processes than this PC's observed baseline. Inspect names, signatures and independent findings; volume alone does not identify malware.", "processes"));
        if (freshAlerts && alerts!.Warnings.Count > 0)
            recommendations.Add(new("coverage", "Check sensor coverage",
                $"The alert snapshot reports {alerts.Warnings.Count} collection warning(s). Missing visibility cannot be learned as a healthy or quiet state.", "security-events"));

        var stateOverall = !enabled ? "paused" : !available ? "unavailable" : urgent.Length > 0 || unusual.Count > 0 ? "attention"
            : metrics.Any(m => m.State == "unavailable") ? "partial" : metrics.Any(m => m.State == "learning") ? "learning" : "observing";
        return new(1, now, stateOverall, history.LastObservationUtc, historyBuckets.Length, metrics, recommendations,
            warnings.Distinct().Take(8).ToArray());
    }

    private static double?[] Values(LocalLearningFrame frame) => [frame.Cpu, frame.Memory, frame.Connections, frame.Processes];
    private static bool Finite(double value, int metric) => double.IsFinite(value) && value >= 0 && value <= MaximumValues[metric];
    private static DateTimeOffset Minute(DateTimeOffset at) => new(at.UtcDateTime.Year, at.UtcDateTime.Month, at.UtcDateTime.Day,
        at.UtcDateTime.Hour, at.UtcDateTime.Minute, 0, TimeSpan.Zero);
    private static DateTimeOffset Floor(DateTimeOffset at) => Minute(at).AddMinutes(-(at.UtcDateTime.Minute % 5));
    private static double Median(double[] values)
    {
        Array.Sort(values);
        var mid = values.Length / 2;
        return values.Length % 2 == 1 ? values[mid] : (values[mid - 1] + values[mid]) / 2;
    }
}
