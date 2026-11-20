namespace Downpour.Core;

public sealed record RefreshSample(string Route, TimeSpan Duration);

public sealed record RouteBudget(string Route, TimeSpan P95, TimeSpan Budget, bool WithinBudget, int Samples);

/// <summary>
/// Turns "every page refreshes every second without flicker" into something measurable. A route that cannot render a
/// sample inside its budget is reported rather than quietly degrading, and quiet mode derives a throttle factor from
/// the measured cost so an always-on agent does not drain a laptop. Quiet mode only slows collection; it never
/// substitutes synthetic values or claims fresher data than it has.
/// </summary>
public static class RefreshBudget
{
    public static readonly TimeSpan DefaultBudget = TimeSpan.FromMilliseconds(250);

    public static IReadOnlyList<RouteBudget> Evaluate(IEnumerable<RefreshSample> samples, TimeSpan? budget = null)
    {
        ArgumentNullException.ThrowIfNull(samples);
        var limit = budget ?? DefaultBudget;
        if (limit <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(budget));
        return samples
            .Where(sample => !string.IsNullOrWhiteSpace(sample.Route) && sample.Duration >= TimeSpan.Zero)
            .GroupBy(sample => sample.Route, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var ordered = group.Select(sample => sample.Duration).OrderBy(duration => duration).ToArray();
                var p95 = ordered[Math.Clamp((int)Math.Ceiling(0.95 * ordered.Length) - 1, 0, ordered.Length - 1)];
                return new RouteBudget(group.Key, p95, limit, p95 <= limit, ordered.Length);
            })
            .OrderByDescending(route => route.P95)
            .ToArray();
    }

    /// <summary>Multiplier for a collector interval: 1 when the budget is met, up to 10× slower when it is badly missed.</summary>
    public static int QuietModeFactor(RouteBudget route)
    {
        ArgumentNullException.ThrowIfNull(route);
        if (route.WithinBudget || route.Budget <= TimeSpan.Zero) return 1;
        var ratio = route.P95.TotalMilliseconds / route.Budget.TotalMilliseconds;
        return (int)Math.Clamp(Math.Ceiling(ratio), 1, 10);
    }
}
