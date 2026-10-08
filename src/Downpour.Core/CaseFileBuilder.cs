using System.Text;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>Everything a reviewer needs; any part can be missing when its source was unavailable.</summary>
public sealed record CaseFileInputs(
    DateTimeOffset CreatedAt,
    string ProductVersion,
    string WindowsVersion,
    SecurityAlertSnapshot? Alerts,
    ThreatDatabaseSnapshot? ThreatDatabases,
    AntiStalkerSnapshot? AntiStalker,
    HardeningPostureSnapshot? Hardening,
    FirewallSnapshot? Firewall,
    SensorSettingsSnapshot? Settings,
    IReadOnlyList<string> RecentActions,
    IReadOnlyList<string> Unavailable);

/// <summary>
/// Builds a self-contained review file (Markdown with a full JSON appendix) so a second opinion — a person, another
/// security tool, or an AI agent the owner chooses — can double-check findings before anything is changed. It contains
/// metadata only: no file contents, credentials, browser data or command lines.
/// </summary>
public static class CaseFileBuilder
{
    public const int MaximumAlerts = 500;

    private static readonly JsonSerializerSettings Json = new() { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore };

    public static string Build(CaseFileInputs input)
    {
        var md = new StringBuilder();
        md.AppendLine("# Downpour Next case file");
        md.AppendLine();
        md.AppendLine($"Created {input.CreatedAt:yyyy-MM-dd HH:mm:ss zzz} · Downpour Next {input.ProductVersion} · {input.WindowsVersion}");
        md.AppendLine();
        md.AppendLine("## Instructions for the reviewer");
        md.AppendLine();
        md.AppendLine("You are reviewing security findings from a home Windows PC for its owner. For every finding below:");
        md.AppendLine("1. Classify it as **true positive**, **false positive**, or **needs more information**, and say why.");
        md.AppendLine("2. Explain in plain words what the item is, what it does, who publishes or operates it, and whether it is legitimate.");
        md.AppendLine("3. Recommend the least disruptive next step. Prefer reversible actions (quarantine with restore, time-limited firewall block, disable instead of delete). Say what would break if the owner acts.");
        md.AppendLine("4. Do not run commands or change anything yourself; the owner confirms every action inside Downpour.");
        md.AppendLine("Downpour's own verdicts and confidence scores are included with their reasons; challenge them where the evidence is weak.");
        md.AppendLine();
        if (input.Unavailable.Count > 0)
        {
            md.AppendLine("## Sources that were unavailable");
            foreach (var item in input.Unavailable) md.AppendLine($"- {Clean(item)}");
            md.AppendLine();
        }

        var alerts = input.Alerts?.Alerts.Where(a => a.State is not "Dismissed").OrderByDescending(a => Rank(a.Severity)).ThenByDescending(a => a.LastSeenUtc).Take(MaximumAlerts).ToArray() ?? [];
        md.AppendLine($"## Open alerts ({alerts.Length})");
        md.AppendLine();
        if (alerts.Length == 0) md.AppendLine("None.");
        foreach (var a in alerts)
            md.AppendLine($"- **{a.Severity}** · {a.State}{(a.IsVerified ? " · user-verified" : "")} · {Clean(a.Title)} · source {Clean(a.LogName)} · MITRE {a.Technique} · seen {a.Occurrences}× between {a.FirstSeenUtc:u} and {a.LastSeenUtc:u}");
        md.AppendLine();

        if (input.ThreatDatabases is { } db)
        {
            md.AppendLine($"## Threat database matches ({db.Matches.Count})");
            md.AppendLine();
            md.AppendLine($"{db.TotalIndicators:N0} indicators from {db.Feeds.Count(f => f.Entries > 0)} databases. Last sweep {db.Coverage.LastSweepUtc?.ToString("u") ?? "pending"}: {db.Coverage.ConnectionsChecked} connections, {db.Coverage.DomainsChecked} DNS names, {db.Coverage.DriversHashed} drivers, {db.Coverage.ProgramsHashed} programs checked.");
            md.AppendLine();
            foreach (var m in db.Matches)
            {
                md.AppendLine($"### {m.Severity} · {ThreatVerdicts.Label(m.Verdict)} ({m.Confidence}%) · {Clean(m.Label)}");
                md.AppendLine($"- Where: {m.Where} — {Clean(m.Subject)}");
                md.AppendLine($"- Indicator: `{Clean(m.Indicator)}` · listed by {Clean(m.FeedName)} · MITRE {m.Technique}");
                foreach (var reason in m.Reasons ?? []) md.AppendLine($"- {Clean(reason)}");
            }
            md.AppendLine();
            md.AppendLine("### Internet connections at the last sweep");
            foreach (var c in db.Connections.Take(150))
                md.AppendLine($"- {Clean(c.Program)} (PID {c.ProcessId}) → {c.RemoteAddress}:{c.RemotePort} · {c.CountryCode ?? "??"} · {(c.Asn is { } asn ? $"AS{asn} {Clean(c.Network ?? "")}" : "network unknown")}{(c.Listed ? " · **LISTED**" : "")}");
            md.AppendLine();
        }

        if (input.AntiStalker is { } watch)
        {
            md.AppendLine("## Anti-stalker state");
            foreach (var u in watch.SensorUsage.Where(u => u.InUse)) md.AppendLine($"- In use now: {WatchCapabilities.Label(u.Capability)} by {Clean(u.DisplayName)}");
            foreach (var r in watch.RemoteSessions) md.AppendLine($"- Remote session {r.SessionId}: {r.State} via {r.Protocol}{(r.ClientName is { } n ? $" from {Clean(n)}" : "")}{(r.ClientAddress is { } ip ? $" ({ip})" : "")}");
            foreach (var t in watch.RemoteControl) md.AppendLine($"- Remote-control program running: {Clean(t.Product)} ({Clean(t.ProcessName)}, {t.Category})");
            foreach (var s in watch.Monitoring) md.AppendLine($"- Monitoring software: {Clean(s.Product)} ({s.Category}, {s.Severity}, found in {s.Source})");
            foreach (var e in watch.Log.Take(40)) md.AppendLine($"- {e.TimeUtc:u} {e.Kind}: {Clean(e.Subject)} — {Clean(e.Detail)}");
            md.AppendLine();
        }

        if (input.Hardening is { } hardening)
        {
            md.AppendLine("## Hardening checks (recommendations, not attacks)");
            foreach (var c in hardening.Checks.Where(c => c.State == PostureStates.Finding)) md.AppendLine($"- {c.Severity} · {Clean(c.Title)}: {Clean(c.Detail)}");
            md.AppendLine();
        }
        if (input.Firewall is { } firewall)
        {
            md.AppendLine("## Firewall findings");
            foreach (var f in firewall.Findings) md.AppendLine($"- {f.Severity} · {Clean(f.Summary)}");
            md.AppendLine();
        }
        if (input.Settings is { } settings)
        {
            md.AppendLine("## Response-action switches");
            md.AppendLine($"Quarantine {On(settings.QuarantineActions)} · process termination {On(settings.ProcessTerminationActions)} · firewall {On(settings.FirewallActions)} · USB {On(settings.UsbActions)} · host isolation {On(settings.HostIsolationActions)} · threat database updates {On(settings.ThreatDatabases)}. Every action still needs per-request confirmation.");
            md.AppendLine();
        }
        md.AppendLine($"## Recent actions taken in Downpour ({input.RecentActions.Count})");
        if (input.RecentActions.Count == 0) md.AppendLine("None recorded.");
        foreach (var line in input.RecentActions) md.AppendLine($"- `{Clean(line)}`");
        md.AppendLine();

        md.AppendLine("## Machine-readable data");
        md.AppendLine();
        md.AppendLine("```json");
        md.AppendLine(JsonConvert.SerializeObject(new
        {
            schema = "downpour-case-file/1",
            createdAt = input.CreatedAt,
            input.ProductVersion,
            input.WindowsVersion,
            alerts,
            threatDatabaseMatches = input.ThreatDatabases?.Matches,
            connections = input.ThreatDatabases?.Connections,
            antiStalker = input.AntiStalker,
            hardeningFindings = input.Hardening?.Checks.Where(c => c.State == PostureStates.Finding),
            firewallFindings = input.Firewall?.Findings,
            settings = input.Settings,
            input.RecentActions,
            input.Unavailable,
        }, Json));
        md.AppendLine("```");
        return md.ToString();
    }

    private static string On(bool value) => value ? "on" : "off";
    private static int Rank(string severity) => severity switch { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, _ => 1 };
    private static string Clean(string value) => new(value.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
}
