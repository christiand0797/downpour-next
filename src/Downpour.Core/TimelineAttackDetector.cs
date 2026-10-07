using System.Net;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed record TimelineAttackFinding(
    string Severity,
    string Title,
    string Description,
    string Technique,
    IReadOnlyList<string> EvidenceIds,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc);

/// <summary>
/// Correlation engine and HTML report generator for security timeline events.
/// Ported from v29 _tl_detect_attacks and _tl_export_html.
/// </summary>
public static class TimelineAttackDetector
{
    public static IReadOnlyList<TimelineAttackFinding> Detect(IEnumerable<SecurityAlert> alerts)
    {
        var alertList = alerts?.ToList() ?? [];
        if (alertList.Count == 0) return [];

        var findings = new List<TimelineAttackFinding>();

        // 1. Brute Force Detection: 5 or more Event 4625 (Failed Logon)
        var failedLogons = alertList.Where(a => a.EventId == 4625).ToList();
        if (failedLogons.Count >= 5)
        {
            var totalOccurrences = failedLogons.Sum(a => Math.Max(1, a.Occurrences));
            var first = failedLogons.Min(a => a.EventTimeUtc);
            var last = failedLogons.Max(a => a.EventTimeUtc);
            findings.Add(new TimelineAttackFinding(
                "CRITICAL",
                "Brute Force Authentication Pattern",
                $"Observed {totalOccurrences} failed logon attempts across {failedLogons.Count} alert record(s) (Event ID 4625).",
                "T1110.001",
                failedLogons.Select(a => a.AlertId).Distinct().ToArray(),
                first,
                last));
        }

        // 2. Account Manipulation: Event 4720 (User Created), 4728/4732/4756 (Member Added), 4722 (Enabled), 4724 (Reset)
        var accountChanges = alertList.Where(a => a.EventId is 4720 or 4722 or 4724 or 4728 or 4732 or 4756).ToList();
        if (accountChanges.Count > 0)
        {
            var first = accountChanges.Min(a => a.EventTimeUtc);
            var last = accountChanges.Max(a => a.EventTimeUtc);
            var eventSummaries = string.Join(", ", accountChanges.Select(a => $"{a.Title} (Event {a.EventId})").Distinct().Take(3));
            findings.Add(new TimelineAttackFinding(
                "HIGH",
                "Privileged Account Manipulation",
                $"Detected {accountChanges.Count} account modification event(s): {eventSummaries}.",
                "T1098",
                accountChanges.Select(a => a.AlertId).Distinct().ToArray(),
                first,
                last));
        }

        // 3. Service Installation: Event 4697, 7045
        var serviceInstalls = alertList.Where(a => a.EventId is 4697 or 7045).ToList();
        if (serviceInstalls.Count > 0)
        {
            var first = serviceInstalls.Min(a => a.EventTimeUtc);
            var last = serviceInstalls.Max(a => a.EventTimeUtc);
            findings.Add(new TimelineAttackFinding(
                "HIGH",
                "New Windows Service Installation",
                $"Detected {serviceInstalls.Count} new service installation event(s) (Event ID {string.Join('/', serviceInstalls.Select(a => a.EventId).Distinct())}).",
                "T1543.003",
                serviceInstalls.Select(a => a.AlertId).Distinct().ToArray(),
                first,
                last));
        }

        // 4. Scheduled Task Creation/Modification: Event 4698, 4702
        var taskChanges = alertList.Where(a => a.EventId is 4698 or 4702).ToList();
        if (taskChanges.Count > 0)
        {
            var first = taskChanges.Min(a => a.EventTimeUtc);
            var last = taskChanges.Max(a => a.EventTimeUtc);
            findings.Add(new TimelineAttackFinding(
                "HIGH",
                "Scheduled Task Persistence Activity",
                $"Detected {taskChanges.Count} scheduled task creation or modification event(s).",
                "T1053.005",
                taskChanges.Select(a => a.AlertId).Distinct().ToArray(),
                first,
                last));
        }

        // 5. Explicit Credential Use / Lateral Movement: Event 4648 (> 3 occurrences)
        var explicitCreds = alertList.Where(a => a.EventId == 4648).ToList();
        if (explicitCreds.Count > 3)
        {
            var first = explicitCreds.Min(a => a.EventTimeUtc);
            var last = explicitCreds.Max(a => a.EventTimeUtc);
            findings.Add(new TimelineAttackFinding(
                "MEDIUM",
                "Explicit Credential Logon Burst",
                $"Detected {explicitCreds.Count} explicit-credential logon events indicating potential lateral movement or credential misuse.",
                "T1078",
                explicitCreds.Select(a => a.AlertId).Distinct().ToArray(),
                first,
                last));
        }

        // 6. Firewall Rule Changes: Event 4946, 4947
        var fwChanges = alertList.Where(a => a.EventId is 4946 or 4947).ToList();
        if (fwChanges.Count > 0)
        {
            var first = fwChanges.Min(a => a.EventTimeUtc);
            var last = fwChanges.Max(a => a.EventTimeUtc);
            findings.Add(new TimelineAttackFinding(
                "MEDIUM",
                "Firewall Rule Modification",
                $"Detected {fwChanges.Count} Windows Firewall rule addition or change event(s).",
                "T1562.004",
                fwChanges.Select(a => a.AlertId).Distinct().ToArray(),
                first,
                last));
        }

        return findings;
    }

    /// <summary>
    /// Generates a self-contained, beautifully styled HTML timeline report matching v29 _tl_export_html.
    /// </summary>
    public static string GenerateHtmlReport(
        IReadOnlyList<SecurityAlert> alerts,
        IReadOnlyList<TimelineAttackFinding> findings,
        string reportTitle = "Downpour Security Event Timeline")
    {
        var sb = new StringBuilder(16384);
        var safeTitle = WebUtility.HtmlEncode(reportTitle);
        var genTime = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"utf-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"  <title>{safeTitle}</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    body { background-color: #080c14; color: #d0d7de; font-family: -apple-system, Segoe UI, Consolas, monospace; font-size: 13px; line-height: 1.5; margin: 0; padding: 24px; }");
        sb.AppendLine("    .container { max-width: 1280px; margin: 0 auto; }");
        sb.AppendLine("    h1 { color: #58a6ff; font-size: 22px; font-weight: 600; margin: 0 0 4px 0; }");
        sb.AppendLine("    .meta { color: #8b949e; font-size: 12px; margin-bottom: 24px; }");
        sb.AppendLine("    .findings-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 24px; }");
        sb.AppendLine("    .findings-title { font-size: 15px; font-weight: 600; color: #f0883e; margin-bottom: 12px; }");
        sb.AppendLine("    .finding-item { background: #0d1117; border-left: 4px solid #f85149; padding: 8px 12px; margin-bottom: 8px; border-radius: 0 4px 4px 0; }");
        sb.AppendLine("    .finding-item.HIGH { border-left-color: #f0883e; }");
        sb.AppendLine("    .finding-item.MEDIUM { border-left-color: #d29922; }");
        sb.AppendLine("    .finding-title { font-weight: 600; color: #f0f6fc; }");
        sb.AppendLine("    .finding-desc { color: #8b949e; font-size: 12px; margin-top: 2px; }");
        sb.AppendLine("    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 6px; overflow: hidden; }");
        sb.AppendLine("    th { background: #21262d; color: #8b949e; font-size: 11px; text-transform: uppercase; text-align: left; padding: 10px 12px; border-bottom: 1px solid #30363d; }");
        sb.AppendLine("    td { padding: 8px 12px; border-bottom: 1px solid #21262d; }");
        sb.AppendLine("    tr:hover { background: #1c2128; }");
        sb.AppendLine("    .badge { display: inline-block; padding: 2px 6px; font-size: 10px; font-weight: 600; border-radius: 10px; text-transform: uppercase; }");
        sb.AppendLine("    .badge-CRITICAL { background: #da3633; color: #fff; }");
        sb.AppendLine("    .badge-HIGH { background: #bc4c00; color: #fff; }");
        sb.AppendLine("    .badge-MEDIUM { background: #9e6a03; color: #fff; }");
        sb.AppendLine("    .badge-LOW { background: #388bfd; color: #fff; }");
        sb.AppendLine("    .time { color: #58a6ff; font-variant-numeric: tabular-nums; }");
        sb.AppendLine("    .code { font-family: Consolas, monospace; background: #0d1117; padding: 2px 4px; border-radius: 3px; font-size: 11px; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"container\">");
        sb.AppendLine($"    <h1>🛡️ {safeTitle}</h1>");
        sb.AppendLine($"    <div class=\"meta\">Generated on {genTime} · Total Events: {alerts.Count} · Attack Indicators: {findings.Count}</div>");

        if (findings.Count > 0)
        {
            sb.AppendLine("    <div class=\"findings-card\">");
            sb.AppendLine($"      <div class=\"findings-title\">⚠️ Correlated Attack Indicators ({findings.Count})</div>");
            foreach (var f in findings)
            {
                var sevClass = WebUtility.HtmlEncode(f.Severity);
                sb.AppendLine($"      <div class=\"finding-item {sevClass}\">");
                sb.AppendLine($"        <div class=\"finding-title\"><span class=\"badge badge-{sevClass}\">{sevClass}</span> {WebUtility.HtmlEncode(f.Title)} <span class=\"code\">{WebUtility.HtmlEncode(f.Technique)}</span></div>");
                sb.AppendLine($"        <div class=\"finding-desc\">{WebUtility.HtmlEncode(f.Description)}</div>");
                sb.AppendLine("      </div>");
            }
            sb.AppendLine("    </div>");
        }

        sb.AppendLine("    <table>");
        sb.AppendLine("      <thead>");
        sb.AppendLine("        <tr>");
        sb.AppendLine("          <th>Timestamp (UTC)</th>");
        sb.AppendLine("          <th>Event ID</th>");
        sb.AppendLine("          <th>Severity</th>");
        sb.AppendLine("          <th>Technique</th>");
        sb.AppendLine("          <th>Alert Title</th>");
        sb.AppendLine("          <th>Provider</th>");
        sb.AppendLine("        </tr>");
        sb.AppendLine("      </thead>");
        sb.AppendLine("      <tbody>");

        foreach (var a in alerts.OrderByDescending(x => x.EventTimeUtc))
        {
            var sev = WebUtility.HtmlEncode(a.Severity);
            sb.AppendLine("        <tr>");
            sb.AppendLine($"          <td class=\"time\">{a.EventTimeUtc:yyyy-MM-dd HH:mm:ss}</td>");
            sb.AppendLine($"          <td><span class=\"code\">{a.EventId}</span></td>");
            sb.AppendLine($"          <td><span class=\"badge badge-{sev}\">{sev}</span></td>");
            sb.AppendLine($"          <td><span class=\"code\">{WebUtility.HtmlEncode(a.Technique)}</span></td>");
            sb.AppendLine($"          <td>{WebUtility.HtmlEncode(a.Title)}</td>");
            sb.AppendLine($"          <td>{WebUtility.HtmlEncode(a.Provider)}</td>");
            sb.AppendLine("        </tr>");
        }

        sb.AppendLine("      </tbody>");
        sb.AppendLine("    </table>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }
}
