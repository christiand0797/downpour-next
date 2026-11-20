namespace Downpour.Core;

public sealed record RuleRequirement(string RuleId, string Channel, IReadOnlyList<string> Fields);

public enum RuleState { CanFire, CannotFire, Unknown, Silent }

public sealed record RuleCoverage(string RuleId, RuleState State, string Reason);

/// <summary>
/// Distinguishes a rule that is working and finding nothing from a rule that cannot fire on this PC at all. The second
/// case is a blind spot that looks exactly like calm, so it is called out by name: missing channel, missing field, or a
/// rule that has not fired once in the silence window while its inputs were available.
/// </summary>
public static class RuleCoverageMap
{
    public static readonly TimeSpan DefaultSilenceWindow = TimeSpan.FromDays(30);

    public static IReadOnlyList<RuleCoverage> Assess(
        IEnumerable<RuleRequirement> rules,
        IReadOnlySet<string> availableChannels,
        IReadOnlyDictionary<string, IReadOnlySet<string>> availableFields,
        IReadOnlyDictionary<string, int> fireCounts,
        DateTimeOffset now,
        TimeSpan? silenceWindow = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(availableChannels);
        ArgumentNullException.ThrowIfNull(availableFields);
        ArgumentNullException.ThrowIfNull(fireCounts);
        var window = silenceWindow ?? DefaultSilenceWindow;
        if (window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(silenceWindow));
        // Silence is only meaningful when the caller states that the rule was observed for a full window; without that
        // statement a zero count is simply an absence of evidence.
        var observedLongEnough = silenceWindow is not null;

        return rules
            .Where(rule => !string.IsNullOrWhiteSpace(rule.RuleId))
            .Select(rule =>
            {
                if (string.IsNullOrWhiteSpace(rule.Channel))
                    return new RuleCoverage(rule.RuleId, RuleState.Unknown, "The rule names no channel, so its inputs cannot be checked.");
                if (!availableChannels.Contains(rule.Channel))
                    return new RuleCoverage(rule.RuleId, RuleState.CannotFire, $"Channel {rule.Channel} is not collected on this PC.");
                if (availableFields.TryGetValue(rule.Channel, out var fields))
                {
                    var missing = rule.Fields.Where(field => !fields.Contains(field)).ToArray();
                    if (missing.Length > 0)
                        return new RuleCoverage(rule.RuleId, RuleState.CannotFire, $"Missing field(s) on {rule.Channel}: {string.Join(", ", missing)}.");
                }
                var fired = fireCounts.GetValueOrDefault(rule.RuleId);
                if (fired == 0 && observedLongEnough)
                    return new RuleCoverage(rule.RuleId, RuleState.Silent, $"No match in the last {window.TotalDays:0} days while its inputs were available.");
                return new RuleCoverage(rule.RuleId, RuleState.CanFire, fired == 0
                    ? "Inputs are available; the rule has not been observed long enough to call it silent."
                    : $"Fired {fired:N0} time(s).");
            })
            .OrderBy(coverage => coverage.State == RuleState.CannotFire ? 0 : coverage.State == RuleState.Silent ? 1 : coverage.State == RuleState.Unknown ? 2 : 3)
            .ThenBy(coverage => coverage.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
