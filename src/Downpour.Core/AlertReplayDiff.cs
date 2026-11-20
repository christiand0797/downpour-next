namespace Downpour.Core;

public sealed record ReplayedAlert(string DedupKey, string Severity, string RuleId);

public sealed record ReplayDifference(string DedupKey, string Problem);

/// <summary>
/// Compares a recorded event/feed corpus replayed through the current parsers and repository with the alert set the
/// same corpus produced before. This is how a precision regression gets caught by a gate instead of by a user: a rule
/// that starts firing on benign records shows up as an unexpected alert, and a detection that stops firing shows up as
/// a missing one.
/// </summary>
public static class AlertReplayDiff
{
    public const int MaximumAlerts = 10_000;

    public static IReadOnlyList<ReplayDifference> Compare(IEnumerable<ReplayedAlert> expected, IEnumerable<ReplayedAlert> actual)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(actual);
        var expectedByKey = expected.Take(MaximumAlerts).GroupBy(alert => alert.DedupKey, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        var actualByKey = actual.Take(MaximumAlerts).GroupBy(alert => alert.DedupKey, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        var differences = new List<ReplayDifference>();
        foreach (var (key, alert) in expectedByKey)
        {
            if (!actualByKey.TryGetValue(key, out var produced))
            {
                differences.Add(new(key, $"Expected alert from rule {alert.RuleId} is missing."));
                continue;
            }
            if (!string.Equals(alert.Severity, produced.Severity, StringComparison.Ordinal))
                differences.Add(new(key, $"Severity changed from {alert.Severity} to {produced.Severity}."));
        }
        foreach (var (key, alert) in actualByKey.Where(pair => !expectedByKey.ContainsKey(pair.Key)))
            differences.Add(new(key, $"Unexpected alert from rule {alert.RuleId} at {alert.Severity}."));
        return differences.OrderBy(difference => difference.DedupKey, StringComparer.Ordinal).ToArray();
    }

    public static string Summarize(IReadOnlyList<ReplayDifference> differences) => differences.Count == 0
        ? "Replay matches the recorded expectation."
        : $"{differences.Count:N0} replay difference(s): a precision or coverage change landed with this build.";
}
