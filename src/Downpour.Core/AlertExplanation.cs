using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// The plain-language "why this fired" text for one stored alert, built only from metadata the store already holds.
/// It never claims a confidence score: severity comes from the event catalog, and the boundary that was crossed is the
/// allow-listed event ID itself. Saying what is missing matters as much as saying what matched, because a person who
/// cannot tell the difference between a lead and a conclusion suppresses the lead.
/// </summary>
public static class AlertExplanation
{
    public const int MaximumLength = 1_200;

    public static string ForAlert(SecurityAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        var builder = new StringBuilder(480);
        var ruleName = alert.Title.Split(':')[0].Trim();
        builder.AppendLine($"Rule: {Bound(ruleName)} ({Bound(alert.LogName)} · {Bound(alert.Provider)} · event {alert.EventId})");
        builder.AppendLine($"Severity: {alert.Severity} — a fixed catalog rule for this event ID. Downpour does not infer a confidence score.");
        builder.AppendLine(
            $"Evidence used: channel {Bound(alert.LogName)}, provider {Bound(alert.Provider)}, event {alert.EventId}, " +
            $"record {(alert.RecordId?.ToString() ?? "not available")}, first seen {alert.FirstSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm}, " +
            $"last seen {alert.LastSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm}" +
            (alert.Occurrences > 1 ? $", {alert.Occurrences:N0} occurrences." : "."));
        builder.AppendLine(
            "Not available: the record's contents (never collected), the surrounding log context, and any file signature " +
            "unless this was a service install that could be graded.");
        builder.Append("Verdict boundary: the event ID matched the allow-listed catalog entry, which is what set the severity.");
        if (alert.State == "Suppressed") builder.Append(" This alert is currently suppressed, so it is retained but not surfaced as open.");
        if (alert.IsVerified) builder.Append(" You marked it as a verified threat, so it is treated as a lead you accepted rather than one the engine concluded.");
        var text = builder.ToString();
        return text.Length <= MaximumLength ? text : text[..MaximumLength];
    }

    private static string Bound(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "unspecified";
        var trimmed = value.Trim();
        return trimmed.Length <= 120 ? trimmed : trimmed[..119] + "…";
    }
}
