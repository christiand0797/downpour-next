namespace Downpour.Core;

public sealed record FeedUpdateAssessment(bool Accepted, string? Reason);

/// <summary>
/// Decides whether a freshly parsed feed may replace the last accepted copy. Large lists normally change by a few
/// percent; a collapse to a quarter of the previous size or a fourfold jump usually means truncation, a substituted
/// payload, or a provider changing the export. Rejecting keeps the last good index instead of silently degrading
/// matching. Small feeds are exempt because their counts legitimately swing.
/// </summary>
public static class FeedUpdateGuard
{
    public const double MinimumRetainedFraction = 0.25;
    public const double MaximumGrowthFactor = 4.0;
    public const int MinimumEntriesForComparison = 1_000;

    public static FeedUpdateAssessment Assess(int previousEntries, int newEntries)
    {
        if (newEntries <= 0) return new(false, "The update contained no valid entries, so the last accepted copy was kept.");
        if (previousEntries < MinimumEntriesForComparison) return new(true, null);
        if (newEntries < previousEntries * MinimumRetainedFraction)
            return new(false, $"The update shrank from {previousEntries:N0} to {newEntries:N0} entries, so the last accepted copy was kept.");
        if (newEntries > previousEntries * MaximumGrowthFactor)
            return new(false, $"The update grew from {previousEntries:N0} to {newEntries:N0} entries, so the last accepted copy was kept.");
        return new(true, null);
    }
}
