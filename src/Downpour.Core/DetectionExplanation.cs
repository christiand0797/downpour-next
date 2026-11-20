using System.Text;

namespace Downpour.Core;

public sealed record DetectionExplanationInput(
    string RuleId,
    string RuleName,
    string Technique,
    IReadOnlyList<string> ObservedFields,
    IReadOnlyList<string> MissingEvidence,
    string DecisionBoundary,
    int ConfidencePercent);

/// <summary>
/// Builds the "why did this fire" text for one detection. It names the rule, the fields that were used, what evidence was
/// missing, the threshold the verdict crossed and how confident the engine is. The input carries field names and rule
/// metadata only — never a command line, script text or file content — so the explanation is safe to show, log or put in
/// a case pack. A detection the person cannot understand is one they will suppress.
/// </summary>
public static class DetectionExplanation
{
    public const int MaximumTextLength = 1_200;

    public static string Build(DetectionExplanationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.ConfidencePercent is < 0 or > 100) throw new ArgumentOutOfRangeException(nameof(input.ConfidencePercent));
        var builder = new StringBuilder(512);
        builder.AppendLine($"{input.RuleName} ({input.RuleId}) · {input.Technique}");
        builder.AppendLine($"Confidence: {input.ConfidencePercent}%");
        builder.AppendLine($"Evidence used: {(input.ObservedFields.Count == 0 ? "none recorded" : string.Join(", ", input.ObservedFields.Select(Bound)))}");
        builder.AppendLine($"Not available: {(input.MissingEvidence.Count == 0 ? "nothing was missing" : string.Join(", ", input.MissingEvidence.Select(Bound)))}");
        builder.Append($"Verdict boundary: {Bound(input.DecisionBoundary)}");
        var text = builder.ToString();
        return text.Length <= MaximumTextLength ? text : text[..MaximumTextLength];
    }

    /// <summary>A detection with missing evidence is reported as provisional rather than as a confirmed conclusion.</summary>
    public static string ConfidenceLabel(DetectionExplanationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return input.MissingEvidence.Count > 0
            ? "Provisional: some evidence was unavailable, so this is a lead rather than a conclusion."
            : input.ConfidencePercent >= 80 ? "Strong: the available evidence supports the rule's threshold." : "Review: the evidence is present but the threshold was only just met.";
    }

    private static string Bound(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "unspecified";
        var trimmed = value.Trim();
        return trimmed.Length <= 120 ? trimmed : trimmed[..119] + "…";
    }
}
