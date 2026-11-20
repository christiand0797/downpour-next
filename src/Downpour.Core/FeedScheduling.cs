namespace Downpour.Core;

public sealed record FeedDemand(string FeedId, long ApproximateBytes, TimeSpan RefreshInterval, DateTimeOffset? RetrievedUtc, bool FreshnessCritical);

public enum FeedDecision { DownloadNow, DeferMetered, DeferBudget, NotDue }

public sealed record FeedSchedule(string FeedId, FeedDecision Decision, string Reason);

/// <summary>
/// The catalog downloads whole multi-megabyte files. On a tethered connection that is exactly when people disable
/// updates and then report that the database is broken. This scheduler respects a metered flag and a daily byte budget,
/// but never starves the small freshness-critical sources: it defers bulk lists first, and says which sources are
/// deferred and why instead of quietly pausing everything.
/// </summary>
public static class FeedScheduling
{
    public const long DefaultDailyBudgetBytes = 250L * 1024 * 1024;

    public static IReadOnlyList<FeedSchedule> Plan(
        IEnumerable<FeedDemand> feeds,
        DateTimeOffset now,
        bool metered,
        long dailyBudgetBytes = DefaultDailyBudgetBytes)
    {
        ArgumentNullException.ThrowIfNull(feeds);
        if (dailyBudgetBytes < 0) throw new ArgumentOutOfRangeException(nameof(dailyBudgetBytes));
        var remaining = dailyBudgetBytes;
        var schedule = new List<FeedSchedule>();
        // Small, freshness-critical sources first so a budget never starves the lists that change fastest.
        foreach (var feed in feeds.OrderBy(feed => feed.FreshnessCritical ? 0 : 1).ThenBy(feed => feed.ApproximateBytes))
        {
            if (feed.RetrievedUtc is { } retrieved && now - retrieved < feed.RefreshInterval)
            {
                schedule.Add(new FeedSchedule(feed.FeedId, FeedDecision.NotDue, "Not due yet."));
                continue;
            }
            if (metered && !feed.FreshnessCritical)
            {
                schedule.Add(new FeedSchedule(feed.FeedId, FeedDecision.DeferMetered,
                    "This connection is metered; the source is deferred until it is not, or until the download is requested explicitly."));
                continue;
            }
            var cost = Math.Max(0, feed.ApproximateBytes);
            if (cost > remaining && !feed.FreshnessCritical)
            {
                schedule.Add(new FeedSchedule(feed.FeedId, FeedDecision.DeferBudget,
                    "The daily download budget for this session is used; the source will resume on the next budget window."));
                continue;
            }
            remaining = Math.Max(0, remaining - cost);
            schedule.Add(new FeedSchedule(feed.FeedId, FeedDecision.DownloadNow,
                metered ? "Metered connection, but this source is freshness-critical." : "Within the download budget."));
        }
        return schedule.OrderBy(item => item.FeedId, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static string Summarize(IReadOnlyList<FeedSchedule> schedule)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        var deferred = schedule.Count(item => item.Decision is FeedDecision.DeferMetered or FeedDecision.DeferBudget);
        return deferred == 0
            ? $"{schedule.Count(item => item.Decision == FeedDecision.DownloadNow):N0} source(s) will update now."
            : $"{deferred:N0} large source(s) are deferred on this connection; freshness-critical sources still update.";
    }
}
