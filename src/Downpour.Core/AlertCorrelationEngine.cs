using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Builds cautious, deterministic correlations from the bounded alert metadata contract.</summary>
public static class AlertCorrelationEngine
{
    public const int MaximumFindings = 64;

    private static readonly CorrelationRule[] Rules =
    [
        new("service-install-cross-log", "Possible service-install activity across event logs", "HIGH", "T1543.003",
            "System", 7045, "Security", 4697, TimeSpan.FromMinutes(2),
            "Time-proximate corroboration only. Service name, principal, process, and a shared operation identifier are unavailable; these records may describe different installations."),
        new("event-log-clear-cross-log", "Possible event-log clearing activity across event logs", "CRITICAL", "T1070.001",
            "Security", 1102, "System", 104, TimeSpan.FromMinutes(10),
            "Time-proximate corroboration only. Actor, target-log identity, process, and a shared operation identifier are unavailable; these records may describe different actions.")
    ];

    public static IReadOnlyList<CorrelatedAlertFinding> Correlate(SecurityAlertSnapshot snapshot)
    {
        if (!SecurityAlertClient.IsValidSnapshot(snapshot))
            throw new InvalidDataException("The alert snapshot did not pass its data contract validation.");

        var findings = new List<CorrelatedAlertFinding>();
        foreach (var rule in Rules)
        {
            var left = snapshot.Alerts
                .Where(alert => alert.State != "Suppressed" && alert.LogName == rule.LeftLog && alert.EventId == rule.LeftEventId)
                .OrderBy(alert => alert.EventTimeUtc).ThenBy(alert => alert.AlertId, StringComparer.Ordinal).ToArray();
            var right = snapshot.Alerts
                .Where(alert => alert.State != "Suppressed" && alert.LogName == rule.RightLog && alert.EventId == rule.RightEventId)
                .OrderBy(alert => alert.EventTimeUtc).ThenBy(alert => alert.AlertId, StringComparer.Ordinal).ToArray();

            var usedLeft = new HashSet<string>(StringComparer.Ordinal);
            var usedRight = new HashSet<string>(StringComparer.Ordinal);
            var pairs = (from first in left
                         from second in right
                         let distance = (first.EventTimeUtc - second.EventTimeUtc).Duration()
                         where distance <= rule.Window
                         orderby distance, first.EventTimeUtc, first.AlertId, second.AlertId
                         select (First: first, Second: second, Distance: distance)).ToArray();

            foreach (var pair in pairs)
            {
                if (findings.Count >= MaximumFindings) return findings;
                if (usedLeft.Contains(pair.First.AlertId) || usedRight.Contains(pair.Second.AlertId)) continue;
                usedLeft.Add(pair.First.AlertId);
                usedRight.Add(pair.Second.AlertId);

                var evidenceIds = new[] { pair.First.AlertId, pair.Second.AlertId }.Order(StringComparer.Ordinal).ToArray();
                var earlier = pair.First.EventTimeUtc <= pair.Second.EventTimeUtc ? pair.First : pair.Second;
                var later = pair.First.EventTimeUtc <= pair.Second.EventTimeUtc ? pair.Second : pair.First;
                findings.Add(new CorrelatedAlertFinding(
                    CreateFindingId(rule.Id, evidenceIds), rule.Id, rule.Title, rule.Severity, rule.Technique,
                    earlier.EventTimeUtc, later.EventTimeUtc, evidenceIds,
                    $"{pair.First.LogName} event {pair.First.EventId} (record {pair.First.RecordId?.ToString() ?? "unavailable"}) and " +
                    $"{pair.Second.LogName} event {pair.Second.EventId} (record {pair.Second.RecordId?.ToString() ?? "unavailable"}); " +
                    $"observed {pair.Distance.TotalSeconds:N0} seconds apart.", rule.Limitation));
            }
        }

        return findings.OrderByDescending(finding => finding.LastEventUtc)
            .ThenBy(finding => finding.CorrelationId, StringComparer.Ordinal).ToArray();
    }

    private static string CreateFindingId(string ruleId, IReadOnlyList<string> alertIds)
    {
        var material = $"downpour-alert-correlation-v1\n{ruleId}\n{string.Join("\n", alertIds)}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    private sealed record CorrelationRule(
        string Id, string Title, string Severity, string Technique,
        string LeftLog, int LeftEventId, string RightLog, int RightEventId,
        TimeSpan Window, string Limitation);
}

public sealed record CorrelatedAlertFinding(
    string CorrelationId,
    string RuleId,
    string Title,
    string Severity,
    string Technique,
    DateTimeOffset FirstEventUtc,
    DateTimeOffset LastEventUtc,
    IReadOnlyList<string> EvidenceAlertIds,
    string EvidenceSummary,
    string Limitation);
