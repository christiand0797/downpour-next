namespace Downpour.Core;

public sealed record RetentionDay(DateOnly Day, int EvictedAlerts);

public sealed record RetentionReport(
    int Retained,
    int Capacity,
    DateTimeOffset? OldestRetainedUtc,
    TimeSpan Window,
    int EvictedLast7Days,
    IReadOnlyList<string> Warnings);

/// <summary>
/// The alert store keeps a fixed window and a fixed capacity and silently drops whatever does not fit. On a noisy PC the
/// evidence for the incident being investigated can already be gone, with nothing in the UI saying so. This accounts for
/// evictions by day, states when capacity is forcing evidence out ahead of the retention window, and never changes the
/// policy itself.
/// </summary>
public static class StoreRetentionAccounting
{
    public static RetentionReport Assess(
        int retained,
        int capacity,
        DateTimeOffset? oldestRetainedUtc,
        DateTimeOffset now,
        TimeSpan window,
        IEnumerable<RetentionDay> evictions)
    {
        ArgumentNullException.ThrowIfNull(evictions);
        if (retained < 0 || capacity <= 0 || window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(retained));
        var days = evictions.Where(day => day.EvictedAlerts > 0).OrderBy(day => day.Day).ToArray();
        var last7 = days.Where(day => day.Day >= DateOnly.FromDateTime(now.UtcDateTime.AddDays(-7))).Sum(day => day.EvictedAlerts);
        var warnings = new List<string>(3);
        if (retained >= capacity)
            warnings.Add($"The alert store is at its {capacity:N0}-alert capacity, so new alerts push out the oldest evidence before the {window.TotalDays:0}-day window ends.");
        else if (retained >= capacity * 0.9)
            warnings.Add($"The alert store is {retained * 100 / capacity}% full; evidence will start leaving ahead of the {window.TotalDays:0}-day window.");
        // A small store that happens to be young is normal; only a nearly full store can be evicting by capacity.
        if (oldestRetainedUtc is { } oldest && retained >= capacity * 0.9 && now - oldest < window - TimeSpan.FromDays(1))
            warnings.Add($"The oldest retained alert is from {oldest:yyyy-MM-dd}, newer than the {window.TotalDays:0}-day window. Capacity, not age, is evicting evidence.");
        if (last7 > 0)
            warnings.Add($"{last7:N0} alert(s) were evicted in the last seven days.");
        return new RetentionReport(retained, capacity, oldestRetainedUtc, window, last7, warnings);
    }

    public static IReadOnlyList<RetentionDay> SummarizeByDay(IEnumerable<DateTimeOffset> evictedAtUtc) =>
        evictedAtUtc.GroupBy(at => DateOnly.FromDateTime(at.UtcDateTime))
            .Select(group => new RetentionDay(group.Key, group.Count()))
            .OrderBy(day => day.Day)
            .ToArray();
}
