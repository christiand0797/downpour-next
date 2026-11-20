namespace Downpour.Core;

/// <summary>
/// A false-positive suppression with an explicit scope and expiry. The existing store suppresses a fixed
/// channel/provider/event-ID rule indefinitely, which can hide a real detection forever; this record keeps the same
/// evidence but makes the blind spot visible, expiring and countable.
/// </summary>
public sealed record Suppression(
    string RuleKey,
    string Scope,
    DateTimeOffset GrantedUtc,
    DateTimeOffset ExpiresUtc,
    int MatchesSinceGrant,
    int HighestSeverityRank);

public static class SuppressionPolicy
{
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(90);
    public static readonly TimeSpan MinimumLifetime = TimeSpan.FromDays(1);
    public static readonly TimeSpan MaximumLifetime = TimeSpan.FromDays(365);
    private static readonly TimeSpan RenewalWarning = TimeSpan.FromDays(7);

    public static Suppression Grant(string ruleKey, string scope, DateTimeOffset now, int highestSeverityRank, TimeSpan? lifetime = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        if (highestSeverityRank is < 0 or > 4) throw new ArgumentOutOfRangeException(nameof(highestSeverityRank));
        var span = lifetime ?? DefaultLifetime;
        if (span < MinimumLifetime || span > MaximumLifetime)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "A suppression must last between one day and one year.");
        return new Suppression(ruleKey, scope, now, now + span, 0, highestSeverityRank);
    }

    public static bool IsActive(Suppression suppression, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(suppression);
        return now < suppression.ExpiresUtc;
    }

    public static Suppression CountMatch(Suppression suppression, int severityRank)
    {
        ArgumentNullException.ThrowIfNull(suppression);
        return suppression with
        {
            MatchesSinceGrant = suppression.MatchesSinceGrant + 1,
            HighestSeverityRank = Math.Max(suppression.HighestSeverityRank, Math.Clamp(severityRank, 0, 4)),
        };
    }

    public static Suppression Renew(Suppression suppression, DateTimeOffset now, TimeSpan? lifetime = null) =>
        suppression with { ExpiresUtc = now + (lifetime ?? DefaultLifetime) };

    /// <summary>
    /// Suppressions that deserve attention: one that has already hidden a CRITICAL match, one about to lapse, and one
    /// that expired but is still stored. A suppression hiding nothing yet is not a warning.
    /// </summary>
    public static IReadOnlyList<string> Warnings(IEnumerable<Suppression> suppressions, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(suppressions);
        var warnings = new List<string>();
        foreach (var suppression in suppressions)
        {
            if (!IsActive(suppression, now))
            {
                warnings.Add($"Suppression for {suppression.RuleKey} expired on {suppression.ExpiresUtc:yyyy-MM-dd} and should be removed.");
                continue;
            }
            if (suppression.HighestSeverityRank >= 4 && suppression.MatchesSinceGrant > 0)
                warnings.Add($"Suppression for {suppression.RuleKey} has hidden {suppression.MatchesSinceGrant} CRITICAL match(es) since {suppression.GrantedUtc:yyyy-MM-dd}.");
            else if (suppression.ExpiresUtc - now <= RenewalWarning)
                warnings.Add($"Suppression for {suppression.RuleKey} lapses on {suppression.ExpiresUtc:yyyy-MM-dd}; renew it deliberately or let it expire.");
        }
        return warnings;
    }
}
