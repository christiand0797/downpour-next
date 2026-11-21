using System.Globalization;
using System.Text;

namespace Downpour.Core;

/// <summary>
/// One week of stored facts. A null count means this build cannot prove the number, and the digest says "not recorded"
/// instead of printing a zero that reads as a finding of absence.
/// </summary>
public sealed record DigestInputs(
    DateTimeOffset SinceUtc,
    DateTimeOffset NowUtc,
    int? NewAutostarts,
    int? HiddenMatches,
    int? SuppressionsExpired,
    int? SensorsBlind,
    int? FindingsAwaitingReview,
    int? FindingsResolved,
    int? OldestOpenDays,
    string? MostActiveRule,
    int? FindingsAcknowledged = null);

/// <summary>
/// Turns a week of stored state into a short local narrative: what changed, what was hidden, what expired, which sensors
/// could not see, and what is still waiting for a person. Email digests and telemetry are explicitly not part of this; the
/// file is written locally and contains only counts already stored.
/// </summary>
public static class WeeklyDigest
{
    public const int MaximumLines = 40;
    public const int MaximumNotRecorded = 4;

    public static string Build(DigestInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        if (inputs.NowUtc < inputs.SinceUtc) throw new ArgumentOutOfRangeException(nameof(inputs));
        var builder = new StringBuilder(1_024);
        var notRecorded = new List<string>();
        var changes = new List<string>();

        if (inputs.NewAutostarts is { } autostarts)
        {
            if (autostarts > 0) changes.Add($"- {autostarts:N0} new autostart(s) appeared.");
        }
        else notRecorded.Add("Autostart changes are not recorded by this build.");

        if (inputs.HiddenMatches is { } hidden)
        {
            if (hidden > 0) changes.Add($"- {hidden:N0} match(es) were hidden by false-positive suppressions.");
        }
        else notRecorded.Add("Suppression-hidden matches are unavailable while the alert store is offline.");

        if (inputs.SuppressionsExpired is { } expired)
        {
            if (expired > 0) changes.Add($"- {expired:N0} suppression(s) expired and stopped hiding matches.");
        }
        else notRecorded.Add("Expired suppressions are not recorded by this build.");

        if (inputs.SensorsBlind is { } blind)
        {
            if (blind > 0) changes.Add($"- {blind:N0} sensor(s) could not read their source; the related detections were not running.");
        }
        else notRecorded.Add("Sensor readability is not recorded by this build.");

        var quiet = inputs.NewAutostarts == 0 && inputs.HiddenMatches == 0 && inputs.SensorsBlind == 0 && changes.Count == 0;
        builder.AppendLine($"# Downpour weekly summary — {inputs.SinceUtc:yyyy-MM-dd} to {inputs.NowUtc:yyyy-MM-dd}");
        builder.AppendLine();
        builder.AppendLine(quiet
            ? "A quiet week: no new autostarts, nothing newly hidden, and every sensor reported in."
            : "This week's changes:");
        foreach (var line in changes) builder.AppendLine(line);
        builder.AppendLine();

        builder.AppendLine("## Waiting for you");
        builder.AppendLine(inputs.FindingsAwaitingReview switch
        {
            null => "- The review backlog is unavailable while the alert store is offline.",
            0 => "- Nothing is waiting for review.",
            var count => $"- {count:N0} finding(s) await review; the oldest has been open {inputs.OldestOpenDays.GetValueOrDefault():N0} day(s).",
        });
        if (inputs.FindingsAcknowledged is > 0) builder.AppendLine($"- {inputs.FindingsAcknowledged:N0} finding(s) were acknowledged this week.");
        if (inputs.FindingsResolved is > 0) builder.AppendLine($"- {inputs.FindingsResolved:N0} finding(s) were resolved this week.");
        builder.AppendLine();

        builder.AppendLine("## Detection activity");
        builder.AppendLine(inputs.MostActiveRule switch
        {
            null => "- Rule activity is unavailable while the alert store is offline.",
            "" or " " => "- No rule produced a finding this week.",
            var rule => $"- Most active rule: {rule}.",
        });

        if (notRecorded.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("## Not recorded");
            foreach (var line in notRecorded.Take(MaximumNotRecorded)) builder.AppendLine($"- {line}");
        }

        var lines = builder.ToString().Split('\n');
        return lines.Length <= MaximumLines ? builder.ToString() : string.Join('\n', lines.Take(MaximumLines));
    }
}

/// <summary>Names the report by ISO week so one week's file is never overwritten by the next one's.</summary>
public static class WeeklyDigestCalendar
{
    /// <summary>e.g. <c>weekly-2026-W47.md</c>. The ISO year can differ from the calendar year around New Year.</summary>
    public static string FileName(DateTimeOffset nowUtc)
    {
        var utc = nowUtc.UtcDateTime;
        return $"weekly-{ISOWeek.GetYear(utc)}-W{ISOWeek.GetWeekOfYear(utc):00}.md";
    }
}

/// <summary>Maps what the alert store actually records onto the digest. Unavailable facts stay null.</summary>
public static class WeeklyDigestInputs
{
    public static DigestInputs FromFacts(Contracts.WeeklyDigestFacts facts, DateTimeOffset sinceUtc, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(facts);
        return new DigestInputs(
            sinceUtc,
            nowUtc,
            // No weekly autostart history is stored anywhere, so this is never claimed.
            NewAutostarts: null,
            HiddenMatches: facts.HiddenMatches,
            SuppressionsExpired: facts.SuppressionsExpired,
            SensorsBlind: facts.SensorsBlind,
            FindingsAwaitingReview: facts.OpenNow,
            // The alert store has no "Resolved" state, so nothing here is called resolved.
            FindingsResolved: null,
            OldestOpenDays: facts.OldestOpenDays,
            MostActiveRule: facts.MostActiveRule,
            FindingsAcknowledged: facts.AcknowledgedThisWeek);
    }
}
