namespace Downpour.Core;

/// <summary>
/// One alert's timing. Acknowledgement time is a separate field on purpose: the current alert store records state but
/// not when the state changed, so a caller cannot fabricate a time-to-acknowledge from today's data. Until that
/// timestamp is persisted, the median stays "unavailable" rather than being estimated from last-seen times.
/// </summary>
public sealed record AlertTimingSample(string RuleKey, DateTimeOffset FirstSeenUtc, DateTimeOffset? AcknowledgedUtc, bool Open);

public sealed record RuleVolume(string RuleKey, int Count);

public sealed record OperationsSummary(
    int Open,
    int Acknowledged,
    TimeSpan? MedianAcknowledge,
    TimeSpan? P95OpenAge,
    IReadOnlyList<RuleVolume> Noisiest);

/// <summary>
/// Operator-facing metrics from the local store: how much is open, how long the oldest work has waited, and which rule
/// produces the most rows. These describe workload, not threat severity, and are computed on demand from retained data.
/// </summary>
public static class AlertOperationsMetrics
{
    public static OperationsSummary Compute(IEnumerable<AlertTimingSample> samples, DateTimeOffset now, int topRules = 10)
    {
        ArgumentNullException.ThrowIfNull(samples);
        if (topRules < 1) throw new ArgumentOutOfRangeException(nameof(topRules));
        var all = samples.ToArray();
        var acknowledged = all.Where(sample => sample.AcknowledgedUtc is { } acknowledged && acknowledged >= sample.FirstSeenUtc)
            .Select(sample => sample.AcknowledgedUtc!.Value - sample.FirstSeenUtc).OrderBy(span => span).ToArray();
        var openAges = all.Where(sample => sample.Open && sample.FirstSeenUtc <= now)
            .Select(sample => now - sample.FirstSeenUtc).OrderBy(span => span).ToArray();
        var noisiest = all
            .Where(sample => !string.IsNullOrWhiteSpace(sample.RuleKey))
            .GroupBy(sample => sample.RuleKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => new RuleVolume(group.Key, group.Count()))
            .OrderByDescending(volume => volume.Count)
            .ThenBy(volume => volume.RuleKey, StringComparer.OrdinalIgnoreCase)
            .Take(topRules)
            .ToArray();
        return new OperationsSummary(
            all.Count(sample => sample.Open),
            acknowledged.Length,
            acknowledged.Length == 0 ? null : Median(acknowledged),
            openAges.Length == 0 ? null : Percentile(openAges, 0.95),
            noisiest);
    }

    /// <summary>Middle value, or the midpoint of the two middle values, so an even count is not biased low.</summary>
    private static TimeSpan Median(TimeSpan[] sorted) => sorted.Length % 2 == 1
        ? sorted[sorted.Length / 2]
        : TimeSpan.FromTicks((sorted[sorted.Length / 2 - 1].Ticks + sorted[sorted.Length / 2].Ticks) / 2);

    /// <summary>Nearest-rank percentile over an already sorted array.</summary>
    private static TimeSpan Percentile(TimeSpan[] sorted, double percentile)
    {
        var index = (int)Math.Ceiling(percentile * sorted.Length) - 1;
        return sorted[Math.Clamp(index, 0, sorted.Length - 1)];
    }
}
