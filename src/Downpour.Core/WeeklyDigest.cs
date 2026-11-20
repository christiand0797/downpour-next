using System.Text;

namespace Downpour.Core;

public sealed record DigestInputs(
    DateTimeOffset SinceUtc,
    DateTimeOffset NowUtc,
    int NewAutostarts,
    int HiddenMatches,
    int SuppressionsExpired,
    int SensorsBlind,
    int FindingsAwaitingReview,
    int FindingsResolved,
    int OldestOpenDays,
    string MostActiveRule);

/// <summary>
/// Turns a week of stored state into a short local narrative: what changed, what was hidden, what expired, which sensors
/// could not see, and what is still waiting for a person. Email digests and telemetry are explicitly not part of this; the
/// file is written locally and contains only counts already stored.
/// </summary>
public static class WeeklyDigest
{
    public const int MaximumLines = 40;

    public static string Build(DigestInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        if (inputs.NowUtc < inputs.SinceUtc) throw new ArgumentOutOfRangeException(nameof(inputs));
        var builder = new StringBuilder(1_024);
        builder.AppendLine($"# Downpour weekly summary — {inputs.SinceUtc:yyyy-MM-dd} to {inputs.NowUtc:yyyy-MM-dd}");
        builder.AppendLine();
        builder.AppendLine(inputs.NewAutostarts + inputs.HiddenMatches + inputs.SensorsBlind == 0
            ? "A quiet week: no new autostarts, nothing newly hidden, and every sensor reported in."
            : "This week's changes:");
        if (inputs.NewAutostarts > 0) builder.AppendLine($"- {inputs.NewAutostarts:N0} new autostart(s) appeared.");
        if (inputs.HiddenMatches > 0) builder.AppendLine($"- {inputs.HiddenMatches:N0} match(es) were hidden by false-positive suppressions.");
        if (inputs.SuppressionsExpired > 0) builder.AppendLine($"- {inputs.SuppressionsExpired:N0} suppression(s) expired and stopped hiding matches.");
        if (inputs.SensorsBlind > 0) builder.AppendLine($"- {inputs.SensorsBlind:N0} sensor(s) could not read their source; the related detections were not running.");
        builder.AppendLine();
        builder.AppendLine("## Waiting for you");
        builder.AppendLine(inputs.FindingsAwaitingReview == 0
            ? "- Nothing is waiting for review."
            : $"- {inputs.FindingsAwaitingReview:N0} finding(s) await review; the oldest has been open {inputs.OldestOpenDays:N0} day(s).");
        if (inputs.FindingsResolved > 0) builder.AppendLine($"- {inputs.FindingsResolved:N0} finding(s) were resolved this week.");
        builder.AppendLine();
        builder.AppendLine("## Detection activity");
        builder.AppendLine(string.IsNullOrWhiteSpace(inputs.MostActiveRule)
            ? "- No rule produced a finding this week."
            : $"- Most active rule: {inputs.MostActiveRule}.");
        var lines = builder.ToString().Split('\n');
        return lines.Length <= MaximumLines ? builder.ToString() : string.Join('\n', lines.Take(MaximumLines));
    }
}
