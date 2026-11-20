namespace Downpour.Core;

public enum SensorReadiness { Ready, Degraded, Blind }

/// <summary>One sensor input and whether it is actually producing evidence on this PC.</summary>
public sealed record BlindSpotCheck(string Id, string Area, SensorReadiness State, string Detail, string? Remedy);

/// <summary>
/// Ranks what is not being observed. The product is honest about individual unavailable states but a person should not
/// have to assemble that picture across six pages: blind inputs first (worst first), then degraded ones, each with the
/// single remedy that would fix it. A check that is ready and has no remedy is not noise and is dropped from the list.
/// </summary>
public static class BlindSpotDiagnosis
{
    public static IReadOnlyList<BlindSpotCheck> Rank(IEnumerable<BlindSpotCheck> checks)
    {
        ArgumentNullException.ThrowIfNull(checks);
        return checks
            .Where(check => !string.IsNullOrWhiteSpace(check.Id) && !string.IsNullOrWhiteSpace(check.Area))
            .Where(check => check.State != SensorReadiness.Ready)
            .OrderByDescending(check => check.State == SensorReadiness.Blind)
            .ThenBy(check => string.IsNullOrWhiteSpace(check.Remedy))
            .ThenBy(check => check.Area, StringComparer.OrdinalIgnoreCase)
            .ThenBy(check => check.Id, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static string Summarize(IReadOnlyList<BlindSpotCheck> checks)
    {
        ArgumentNullException.ThrowIfNull(checks);
        var blind = checks.Count(check => check.State == SensorReadiness.Blind);
        var degraded = checks.Count(check => check.State == SensorReadiness.Degraded);
        var fixable = checks.Count(check => !string.IsNullOrWhiteSpace(check.Remedy));
        return blind == 0 && degraded == 0
            ? "Every checked sensor is producing evidence on this PC."
            : $"{blind} blind and {degraded} degraded input(s); {fixable} can be fixed locally. Everything else is observing normally.";
    }
}
