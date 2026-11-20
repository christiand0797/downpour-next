namespace Downpour.Core;

/// <summary>One reviewed detection: the source and rule that produced it, and what the review concluded.</summary>
public sealed record DetectionObservation(string SourceId, string RuleId, bool ConfirmedThreat, bool FalsePositiveConfirmed);

public enum SourceVerdict { InsufficientEvidence, Keep, Promote, Demote }

public sealed record SourceValue(
    string SourceId,
    int Observations,
    int Threats,
    int FalsePositives,
    double Precision,
    SourceVerdict Verdict);

/// <summary>
/// Measures whether a source or rule has ever earned its place. Counts only reviewed outcomes, so an unreviewed alert
/// population cannot promote a noisy source; a source with too few reviews stays "insufficient evidence" instead of
/// being judged on a handful of events. The result is a recommendation for the operator, never an automatic change to
/// which sources run.
/// </summary>
public static class DetectionValueLedger
{
    public const int DefaultMinimumSample = 20;

    public static IReadOnlyList<SourceValue> Summarize(IEnumerable<DetectionObservation> observations, int minimumSample = DefaultMinimumSample)
    {
        ArgumentNullException.ThrowIfNull(observations);
        if (minimumSample < 1) throw new ArgumentOutOfRangeException(nameof(minimumSample));
        return observations
            .Where(observation => !string.IsNullOrWhiteSpace(observation.SourceId))
            .GroupBy(observation => observation.SourceId, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var threats = group.Count(observation => observation.ConfirmedThreat);
                var falsePositives = group.Count(observation => observation.FalsePositiveConfirmed);
                var reviewed = threats + falsePositives;
                var precision = reviewed == 0 ? 0 : (double)threats / reviewed;
                var verdict = reviewed < minimumSample ? SourceVerdict.InsufficientEvidence
                    : precision >= 0.6 ? SourceVerdict.Promote
                    : falsePositives >= reviewed * 0.5 ? SourceVerdict.Demote
                    : SourceVerdict.Keep;
                return new SourceValue(group.Key, group.Count(), threats, falsePositives, Math.Round(precision, 3), verdict);
            })
            .OrderByDescending(value => value.Verdict == SourceVerdict.Demote)
            .ThenByDescending(value => value.Observations)
            .ThenBy(value => value.SourceId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Rules inside one source, so an operator can see which rule is noisy rather than condemning the whole feed.
    /// Rules with no reviews are omitted instead of being reported as clean.
    /// </summary>
    public static IReadOnlyList<SourceValue> SummarizeRules(IEnumerable<DetectionObservation> observations, string sourceId, int minimumSample = 5)
    {
        ArgumentNullException.ThrowIfNull(observations);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceId);
        return Summarize(observations
            .Where(observation => string.Equals(observation.SourceId, sourceId, StringComparison.OrdinalIgnoreCase))
            .Select(observation => observation with { SourceId = string.IsNullOrWhiteSpace(observation.RuleId) ? "unnamed rule" : observation.RuleId }),
            minimumSample);
    }
}
