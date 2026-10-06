using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Point-in-time firewall posture findings derived from v29 firewall_tamper_detector.py.
/// v29 alerted on transitions (profile ON→OFF, newly added inbound allow rules) by diffing polls;
/// this analyzer reports the current state, so an existing rule is a "review" item rather than a "new rule" alert.
/// </summary>
public static partial class FirewallRuleAnalyzer
{
    /// <summary>v29 SUSPICIOUS_ALLOW_PORTS (firewall_tamper_detector.py line 31).</summary>
    public static readonly IReadOnlySet<int> SuspiciousAllowPorts = new HashSet<int>
    {
        21, 22, 23, 25, 53, 69, 135, 139, 445, 1433, 1521,
        3306, 3389, 4444, 4445, 5432, 5555, 5900, 5985, 5986,
        6666, 6667, 6697, 8080, 8443, 8888, 9001, 9050,
    };

    private const string Technique = "T1562.004";
    private const int MaximumFindings = 128;

    /// <summary>v29 port_firewall_unblock.py identifies Downpour-created rules with ^downpour (case-insensitive).</summary>
    public static bool IsDownpourRule(string name) => DownpourPrefix().IsMatch(name);

    public static IReadOnlyList<FirewallFinding> Analyze(string serviceState, IReadOnlyList<FirewallProfileState> profiles, IReadOnlyList<FirewallRuleEntry> rules)
    {
        var findings = new List<FirewallFinding>();
        if (serviceState is "Stopped")
            findings.Add(new("CRITICAL", Technique, "Windows Firewall service (MpsSvc) is stopped.", "MpsSvc:Stopped"));

        foreach (var profile in profiles.Where(profile => profile.Enabled == false))
            findings.Add(new(profile.IsActive ? "CRITICAL" : "HIGH", Technique,
                $"Firewall is off for the {profile.Profile} profile{(profile.IsActive ? " (active)" : "")}.", $"{profile.Profile}:Off"));

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            if (findings.Count >= MaximumFindings) break;
            if (!rule.Enabled || rule.Direction != "Inbound" || rule.Action != "Allow") continue;
            // Windows "allow an app" rules are scoped to a program, service, or Store app package with any port; that is
            // normal, so an any-port rule is only reported when it is not scoped at all (the whole port range is open).
            var scoped = rule.Application.Length > 0 || rule.Service.Length > 0 || rule.AppPackage.Length > 0;
            var anyPort = IsAnyPort(rule.LocalPorts);
            // Port-less protocols (ICMP, GRE, ...) never expose TCP/UDP ports.
            var portProtocol = rule.Protocol is "TCP" or "UDP" or "Any";
            IReadOnlyList<int> ports = !portProtocol || (anyPort && scoped) ? []
                : anyPort ? SuspiciousAllowPorts.Order().ToArray()
                : SuspiciousPortsIn(rule.LocalPorts);
            if (ports.Count > 0)
            {
                var summary = anyPort
                    ? $"Enabled inbound allow rule opens every port to any program: {rule.Name}"
                    : $"Enabled inbound allow rule exposes commonly attacked port{(ports.Count == 1 ? "" : "s")} {string.Join(", ", ports)}: {rule.Name}";
                if (seen.Add(summary)) findings.Add(new(anyPort ? "HIGH" : "MEDIUM", Technique, summary, $"{rule.Name}|{rule.LocalPorts}"));
            }
            if (IsStagingPath(rule.Application))
            {
                var summary = $"Enabled inbound allow rule for a program in a temporary or download folder: {rule.Name}";
                if (seen.Add(summary)) findings.Add(new("HIGH", Technique, summary, rule.Application));
            }
        }
        return findings;
    }

    /// <summary>
    /// Exact port and range matching. v29 used substring matching ("445" matched "4450"); this fixes that.
    /// "*" or "Any" means all ports and is reported as covering every suspicious port.
    /// </summary>
    public static IReadOnlyList<int> SuspiciousPortsIn(string localPorts)
    {
        if (string.IsNullOrWhiteSpace(localPorts)) return [];
        var found = new SortedSet<int>();
        foreach (var raw in localPorts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw is "*" || raw.Equals("Any", StringComparison.OrdinalIgnoreCase))
            {
                found.UnionWith(SuspiciousAllowPorts);
                continue;
            }
            var dash = raw.IndexOf('-');
            if (dash > 0 && int.TryParse(raw[..dash], out var low) && int.TryParse(raw[(dash + 1)..], out var high) && low <= high)
                found.UnionWith(SuspiciousAllowPorts.Where(port => port >= low && port <= high));
            else if (int.TryParse(raw, out var single) && SuspiciousAllowPorts.Contains(single))
                found.Add(single);
        }
        return found.ToArray();
    }

    private static bool IsAnyPort(string localPorts) =>
        string.IsNullOrWhiteSpace(localPorts) || localPorts.Trim() is "*" || localPorts.Trim().Equals("Any", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Malware staging locations (Temp, Downloads, Users\Public). Per-user installs under AppData are common for
    /// legitimate software and are deliberately not flagged.
    /// </summary>
    public static bool IsStagingPath(string application)
    {
        if (string.IsNullOrWhiteSpace(application)) return false;
        return StagingPath().IsMatch(application.Replace('/', '\\'));
    }

    [GeneratedRegex(@"^downpour", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DownpourPrefix();

    [GeneratedRegex(@"\\(Temp|Tmp|Downloads|Users\\Public)\\|^%(TEMP|TMP)%\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StagingPath();
}
