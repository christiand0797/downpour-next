namespace Downpour.Core;

public sealed record AlertGroupingInput(string Source, string Subject, int SeverityRank, DateTimeOffset SeenAtUtc);

public sealed record AlertGroup(
    string Source,
    string Subject,
    int Count,
    int HighestSeverityRank,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc);

/// <summary>
/// Collapses repeated findings that share a source and subject (a feed and a host, a rule and a process) into one
/// row. Grouping is presentation-only: the underlying alerts and their audit records are untouched, so acknowledging
/// or investigating a group still resolves individual evidence. Ordering puts the most severe group first, then the
/// noisiest, which is the order a person should triage.
/// </summary>
public static class AlertGrouping
{
    public static IReadOnlyList<AlertGroup> Group(IEnumerable<AlertGroupingInput> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        return findings
            .Where(finding => !string.IsNullOrWhiteSpace(finding.Source) && !string.IsNullOrWhiteSpace(finding.Subject))
            .GroupBy(finding => (finding.Source, finding.Subject), new GroupKeyComparer())
            .Select(group => new AlertGroup(
                group.Key.Source,
                group.Key.Subject,
                group.Count(),
                group.Max(finding => finding.SeverityRank),
                group.Min(finding => finding.SeenAtUtc),
                group.Max(finding => finding.SeenAtUtc)))
            .OrderByDescending(group => group.HighestSeverityRank)
            .ThenByDescending(group => group.Count)
            .ThenBy(group => group.Source, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private sealed class GroupKeyComparer : IEqualityComparer<(string Source, string Subject)>
    {
        public bool Equals((string Source, string Subject) x, (string Source, string Subject) y) =>
            string.Equals(x.Source, y.Source, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Subject, y.Subject, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Source, string Subject) key) => HashCode.Combine(
            StringComparer.OrdinalIgnoreCase.GetHashCode(key.Source),
            StringComparer.OrdinalIgnoreCase.GetHashCode(key.Subject));
    }
}
