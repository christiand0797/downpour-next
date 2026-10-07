using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public static class ForensicEvidenceCollector
{
    private static readonly Regex Ipv4Regex = new(
        @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        RegexOptions.Compiled);

    private static readonly string[] SuspiciousPersistenceKeywords =
    [
        @"\temp\", @"\appdata\", "powershell", "cmd.exe", "wscript", "cscript", "mshta",
        "certutil", "bitsadmin", "curl", ".vbs", ".js", ".scr", ".pif", ".bat", ".cmd"
    ];

    public static async Task<ForensicEvidenceBundle> CollectAsync(
        SecurityAlertClient? alertClient = null,
        SecurityEventClient? eventClient = null,
        PersistenceInventoryClient? persistenceClient = null,
        FirewallInventoryClient? firewallClient = null,
        NetworkInventoryClient? networkClient = null,
        DriverInventoryClient? driverClient = null,
        TimeSpan? probeTimeout = null,
        CancellationToken cancellationToken = default)
    {
        var artifacts = new List<ForensicArtifactItem>();
        var attackerIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var suspiciousTasks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var alertIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Gather Chain of Custody
        var coc = CollectChainOfCustody();

        // 2. Query sensor sources in parallel with bounded timeout
        var effectiveTimeout = probeTimeout ?? TimeSpan.FromSeconds(2);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(effectiveTimeout);
        var token = timeoutCts.Token;

        var alertTask = Task.Run(async () =>
        {
            try
            {
                alertClient ??= new SecurityAlertClient();
                return await alertClient.TryGetSnapshotAsync(token);
            }
            catch { return null; }
        }, token);

        var eventTask = Task.Run(async () =>
        {
            try
            {
                eventClient ??= new SecurityEventClient();
                return await eventClient.TryGetSnapshotAsync(token);
            }
            catch { return null; }
        }, token);

        var persistTask = Task.Run(async () =>
        {
            try
            {
                persistenceClient ??= new PersistenceInventoryClient();
                return await persistenceClient.TryGetSnapshotAsync(token);
            }
            catch { return null; }
        }, token);

        var fwTask = Task.Run(async () =>
        {
            try
            {
                firewallClient ??= new FirewallInventoryClient();
                return await firewallClient.TryGetSnapshotAsync(token);
            }
            catch { return null; }
        }, token);

        var netTask = Task.Run(async () =>
        {
            try
            {
                networkClient ??= new NetworkInventoryClient();
                return await networkClient.TryGetSnapshotAsync(token);
            }
            catch { return null; }
        }, token);

        var driverTask = Task.Run(async () =>
        {
            try
            {
                driverClient ??= new DriverInventoryClient();
                return await driverClient.TryGetSnapshotAsync(token);
            }
            catch { return null; }
        }, token);

        try
        {
            await Task.WhenAll(alertTask, eventTask, persistTask, fwTask, netTask, driverTask);
        }
        catch
        {
            // Ignore cancellation / timeout
        }

        var alertSnapshot = alertTask.IsCompletedSuccessfully ? alertTask.Result : null;
        var eventSnapshot = eventTask.IsCompletedSuccessfully ? eventTask.Result : null;
        var persistSnapshot = persistTask.IsCompletedSuccessfully ? persistTask.Result : null;
        var fwSnapshot = fwTask.IsCompletedSuccessfully ? fwTask.Result : null;
        var netSnapshot = netTask.IsCompletedSuccessfully ? netTask.Result : null;
        var driverSnapshot = driverTask.IsCompletedSuccessfully ? driverTask.Result : null;

        // Process Security Alerts
        if (alertSnapshot is not null)
        {
            foreach (var alert in alertSnapshot.Alerts)
            {
                alertIds.Add(alert.AlertId);
                artifacts.Add(new ForensicArtifactItem
                {
                    Category = "Security Alert",
                    Title = alert.Title,
                    Detail = $"Log: {alert.LogName} · Provider: {alert.Provider} · Event: {alert.EventId} · Occurrences: {alert.Occurrences} · State: {alert.State}",
                    Severity = alert.Severity,
                    Technique = alert.Technique,
                    TimestampUtc = alert.EventTimeUtc,
                    RawEvidenceReference = $"{alert.LogName}#{alert.RecordId ?? alert.EventId}"
                });

                ExtractIps(alert.Title, attackerIps);
            }
        }

        // Process Security Events
        if (eventSnapshot is not null)
        {
            foreach (var ev in eventSnapshot.Events)
            {
                var category = ClassifyEventCategory(ev.EventId, ev.LogName);
                artifacts.Add(new ForensicArtifactItem
                {
                    Category = category,
                    Title = $"{ev.LogName} Event {ev.EventId}: {ev.Summary}",
                    Detail = $"Provider: {ev.Provider} · Occurrences: {ev.Occurrences} · Record ID: {ev.RecordId}",
                    Severity = ev.Severity,
                    Technique = ev.Technique,
                    TimestampUtc = ev.CreatedAtUtc,
                    RawEvidenceReference = $"{ev.LogName}#{ev.RecordId}"
                });

                ExtractIps(ev.Summary, attackerIps);
            }
        }

        // Process Persistence Items
        if (persistSnapshot is not null)
        {
            foreach (var entry in persistSnapshot.Entries)
            {
                bool isSuspicious = IsSuspiciousPersistence(entry);
                if (isSuspicious)
                {
                    suspiciousTasks.Add($"{entry.Category}: {entry.Name}");
                    artifacts.Add(new ForensicArtifactItem
                    {
                        Category = "Persistence & Autostart",
                        Title = $"Suspicious Persistence: {entry.Name}",
                        Detail = $"Location: {entry.Location} · Command: {entry.Value} · Category: {entry.Category}",
                        Severity = "HIGH",
                        Technique = string.IsNullOrWhiteSpace(entry.Technique) ? "T1547.001" : entry.Technique,
                        TimestampUtc = entry.ChangedAtUtc ?? persistSnapshot.CapturedAtUtc,
                        RawEvidenceReference = entry.Location
                    });
                }
            }

            foreach (var finding in persistSnapshot.Findings)
            {
                artifacts.Add(new ForensicArtifactItem
                {
                    Category = "Persistence & Autostart",
                    Title = $"Persistence Risk: {finding.Summary}",
                    Detail = $"Indicator: {finding.Indicator} · Category: {finding.Category}",
                    Severity = finding.Severity,
                    Technique = finding.Technique,
                    TimestampUtc = persistSnapshot.CapturedAtUtc,
                    RawEvidenceReference = finding.Indicator
                });
            }
        }

        // Process Firewall Items
        if (fwSnapshot is not null)
        {
            if (!fwSnapshot.ServiceState.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                artifacts.Add(new ForensicArtifactItem
                {
                    Category = "Defender & Firewall Tampering",
                    Title = "Windows Firewall Service Not Running",
                    Detail = $"Service state: {fwSnapshot.ServiceState}. Indicates potential host tampering or security defense evasion.",
                    Severity = "CRITICAL",
                    Technique = "T1562.004",
                    TimestampUtc = fwSnapshot.CapturedAtUtc,
                    RawEvidenceReference = $"MpsSvc:{fwSnapshot.ServiceState}"
                });
            }

            foreach (var finding in fwSnapshot.Findings)
            {
                artifacts.Add(new ForensicArtifactItem
                {
                    Category = "Defender & Firewall Tampering",
                    Title = $"Firewall Finding: {finding.Summary}",
                    Detail = $"Indicator: {finding.Indicator}",
                    Severity = finding.Severity,
                    Technique = finding.Technique,
                    TimestampUtc = fwSnapshot.CapturedAtUtc,
                    RawEvidenceReference = finding.Indicator
                });
            }

            foreach (var blocked in fwSnapshot.BlockedConnections)
            {
                var remoteIp = blocked.Direction.Equals("Inbound", StringComparison.OrdinalIgnoreCase)
                    ? blocked.SourceAddress
                    : blocked.DestinationAddress;

                artifacts.Add(new ForensicArtifactItem
                {
                    Category = "Firewall Block Event",
                    Title = $"Blocked Connection: {blocked.SourceAddress} -> {blocked.DestinationAddress}:{blocked.DestinationPort}",
                    Detail = $"Direction: {blocked.Direction} · Protocol: {blocked.Protocol} · App: {blocked.Application}",
                    Severity = "MEDIUM",
                    Technique = "T1071",
                    TimestampUtc = blocked.TimeUtc,
                    RawEvidenceReference = $"Blocked:{remoteIp}:{blocked.DestinationPort}"
                });

                if (!IsLocalIp(remoteIp))
                {
                    attackerIps.Add(remoteIp);
                }
            }
        }

        // Process Network Endpoints
        if (netSnapshot is not null)
        {
            foreach (var conn in netSnapshot.Connections)
            {
                if (conn.State.Equals("Established", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(conn.RemoteEndpoint))
                {
                    var remoteIp = ExtractHostFromEndpoint(conn.RemoteEndpoint);
                    if (!IsLocalIp(remoteIp))
                    {
                        artifacts.Add(new ForensicArtifactItem
                        {
                            Category = "Active Remote Endpoint",
                            Title = $"Active External TCP: {conn.RemoteEndpoint}",
                            Detail = $"Local Endpoint: {conn.LocalEndpoint} · State: {conn.State}",
                            Severity = "LOW",
                            Technique = "T1071",
                            TimestampUtc = netSnapshot.CapturedAtUtc,
                            RawEvidenceReference = $"TCP:{conn.LocalEndpoint}->{conn.RemoteEndpoint}"
                        });

                        attackerIps.Add(remoteIp);
                    }
                }
            }
        }

        // Process Kernel Drivers
        if (driverSnapshot is not null)
        {
            foreach (var driver in driverSnapshot.Drivers)
            {
                if (driver.IsInUserWritableLocation || !driver.IsUnderSystemDrivers)
                {
                    artifacts.Add(new ForensicArtifactItem
                    {
                        Category = "Kernel Driver Anomaly",
                        Title = $"Driver Path Anomaly: {driver.Name}",
                        Detail = $"Path: {driver.ImagePath} · UnderSystemDrivers: {driver.IsUnderSystemDrivers} · UserWritable: {driver.IsInUserWritableLocation}",
                        Severity = "HIGH",
                        Technique = "T1068",
                        TimestampUtc = driverSnapshot.CapturedAtUtc,
                        RawEvidenceReference = driver.ImagePath
                    });
                }
            }
        }

        // Sort artifacts deterministically for cryptographic canonicalization
        var sortedArtifacts = artifacts
            .OrderByDescending(a => SeverityWeight(a.Severity))
            .ThenBy(a => a.Category, StringComparer.Ordinal)
            .ThenBy(a => a.Title, StringComparer.Ordinal)
            .ToList();

        // Calculate cryptographic SHA-256 seal
        var hash = ComputeEvidenceIntegritySha256(coc, sortedArtifacts, attackerIps.OrderBy(x => x).ToList());
        coc.EvidenceIntegritySha256 = hash;

        return new ForensicEvidenceBundle
        {
            SchemaVersion = 1,
            ChainOfCustody = coc,
            Artifacts = sortedArtifacts,
            AttackerIps = attackerIps.OrderBy(x => x).ToList(),
            SuspiciousPersistenceItems = suspiciousTasks.OrderBy(x => x).ToList(),
            SecurityAlertIds = alertIds.OrderBy(x => x).ToList()
        };
    }

    public static ForensicChainOfCustody CollectChainOfCustody()
    {
        var localIps = new List<string>();
        var macAddresses = new List<string>();

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var mac = ni.GetPhysicalAddress().ToString();
                    if (!string.IsNullOrEmpty(mac) && mac.Length == 12)
                    {
                        mac = string.Join(":", Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2)));
                        macAddresses.Add(mac);
                    }

                    var ipProps = ni.GetIPProperties();
                    foreach (var addr in ipProps.UnicastAddresses)
                    {
                        var ip = addr.Address.ToString();
                        if (!ip.StartsWith("127.", StringComparison.Ordinal) && ip != "::1")
                        {
                            localIps.Add(ip);
                        }
                    }
                }
            }
        }
        catch
        {
            // Safe fallback
        }

        return new ForensicChainOfCustody
        {
            Hostname = Environment.MachineName,
            OsDescription = RuntimeInformation.OSDescription,
            OsArchitecture = RuntimeInformation.OSArchitecture.ToString(),
            CollectorVersion = "Downpour Next v0.1.14",
            CollectedAtUtc = DateTimeOffset.UtcNow,
            LocalIpAddresses = localIps.Count > 0 ? string.Join(", ", localIps.Distinct()) : "Unknown",
            MacAddresses = macAddresses.Count > 0 ? string.Join(", ", macAddresses.Distinct()) : "Unknown"
        };
    }

    private static string ClassifyEventCategory(int eventId, string logName)
    {
        return eventId switch
        {
            4625 or 4720 or 4726 or 4732 or 4740 => "Account Compromise",
            5001 or 5007 or 5010 or 5012 => "Defender Tampering",
            21 or 25 or 1149 => "RDP Session",
            5152 or 5157 => "Firewall Event",
            1102 or 104 or 7045 => "System Tampering",
            _ => logName.Contains("TerminalServices", StringComparison.OrdinalIgnoreCase) ? "RDP Session" : "Security Event"
        };
    }

    private static bool IsSuspiciousPersistence(PersistenceEntry entry)
    {
        var combined = $"{entry.Location} {entry.Value} {entry.Name}".ToLowerInvariant();
        return SuspiciousPersistenceKeywords.Any(k => combined.Contains(k, StringComparison.OrdinalIgnoreCase)) ||
               (entry.Indicators is { Count: > 0 });
    }

    private static bool IsLocalIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return true;
        return ip.StartsWith("127.", StringComparison.Ordinal) ||
               ip == "0.0.0.0" ||
               ip == "::1" ||
               ip.StartsWith("10.", StringComparison.Ordinal) ||
               ip.StartsWith("192.168.", StringComparison.Ordinal) ||
               ip.StartsWith("169.254.", StringComparison.Ordinal);
    }

    private static string ExtractHostFromEndpoint(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return "";
        var lastColon = endpoint.LastIndexOf(':');
        if (lastColon <= 0) return endpoint;
        var host = endpoint[..lastColon].Trim('[', ']');
        return host;
    }

    private static void ExtractIps(string? text, HashSet<string> destination)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        var matches = Ipv4Regex.Matches(text);
        foreach (Match match in matches)
        {
            var ip = match.Value;
            if (!IsLocalIp(ip))
            {
                destination.Add(ip);
            }
        }
    }

    private static int SeverityWeight(string severity)
    {
        return severity.ToUpperInvariant() switch
        {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0
        };
    }

    public static string ComputeEvidenceIntegritySha256(
        ForensicChainOfCustody coc,
        IReadOnlyList<ForensicArtifactItem> artifacts,
        IReadOnlyList<string> attackerIps)
    {
        var sb = new StringBuilder();
        sb.Append(coc.Hostname).Append('|')
          .Append(coc.OsDescription).Append('|')
          .Append(coc.OsArchitecture).Append('|')
          .Append(coc.CollectorVersion).Append('|')
          .Append(coc.CollectedAtUtc.ToString("o")).Append('|')
          .Append(coc.LocalIpAddresses).Append('|')
          .Append(coc.MacAddresses).Append('\n');

        foreach (var ip in attackerIps)
        {
            sb.Append("IP:").Append(ip).Append('\n');
        }

        foreach (var art in artifacts)
        {
            sb.Append(art.Category).Append('|')
              .Append(art.Severity).Append('|')
              .Append(art.Technique ?? "").Append('|')
              .Append(art.Title).Append('|')
              .Append(art.Detail).Append('|')
              .Append(art.TimestampUtc?.ToString("o") ?? "").Append('\n');
        }

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        var hashBytes = SHA256.HashData(bytes);
        return Convert.ToHexStringLower(hashBytes);
    }

    public static string GenerateJsonBundle(ForensicEvidenceBundle bundle)
    {
        return JsonConvert.SerializeObject(bundle, Formatting.Indented);
    }

    public static string GeneratePlainTextSummary(ForensicEvidenceBundle bundle)
    {
        var coc = bundle.ChainOfCustody;
        var sb = new StringBuilder();
        sb.AppendLine("=== DOWNPOUR FORENSIC EVIDENCE REPORT ===");
        sb.AppendLine("=== DIGITAL CHAIN OF CUSTODY ===");
        sb.AppendLine($"Hostname:        {coc.Hostname}");
        sb.AppendLine($"OS:              {coc.OsDescription} ({coc.OsArchitecture})");
        sb.AppendLine($"Local IP(s):     {coc.LocalIpAddresses}");
        sb.AppendLine($"MAC Address(es): {coc.MacAddresses}");
        sb.AppendLine($"Collector:       {coc.CollectorVersion}");
        sb.AppendLine($"Collected (UTC): {coc.CollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"SHA-256 Seal:    {coc.EvidenceIntegritySha256}");
        sb.AppendLine();

        sb.AppendLine($"=== TOTAL EVIDENCE ITEMS: {bundle.TotalEvidenceCount} ===");
        sb.AppendLine($"Attacker/Remote IPs:         {bundle.AttackerIps.Count}");
        sb.AppendLine($"Suspicious Persistence:      {bundle.SuspiciousPersistenceItems.Count}");
        sb.AppendLine($"Security Alerts Correlated:  {bundle.SecurityAlertIds.Count}");
        sb.AppendLine();

        if (bundle.AttackerIps.Count > 0)
        {
            sb.AppendLine("=== ATTACKER & REMOTE IPS ===");
            foreach (var ip in bundle.AttackerIps)
            {
                sb.AppendLine($"  - {ip}");
            }
            sb.AppendLine();
        }

        if (bundle.SuspiciousPersistenceItems.Count > 0)
        {
            sb.AppendLine("=== SUSPICIOUS PERSISTENCE ITEMS ===");
            foreach (var p in bundle.SuspiciousPersistenceItems)
            {
                sb.AppendLine($"  - {p}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("=== EVIDENCE CATALOG ===");
        foreach (var art in bundle.Artifacts.Take(50))
        {
            var ts = art.TimestampUtc.HasValue ? art.TimestampUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "N/A";
            sb.AppendLine($"[{art.Severity}] [{art.Category}] {art.Title}");
            if (!string.IsNullOrWhiteSpace(art.Technique))
            {
                sb.AppendLine($"   MITRE ATT&CK: {art.Technique}");
            }
            sb.AppendLine($"   Time (UTC): {ts}");
            sb.AppendLine($"   Detail: {art.Detail}");
            sb.AppendLine();
        }

        if (bundle.Artifacts.Count > 50)
        {
            sb.AppendLine($"... and {bundle.Artifacts.Count - 50} additional evidence items in full bundle.");
            sb.AppendLine();
        }

        sb.AppendLine("=== LAW ENFORCEMENT & IC3 SUBMISSION GUIDANCE ===");
        sb.AppendLine("FBI IC3 Online Filing: https://www.ic3.gov");
        sb.AppendLine("- Attach this forensic report and raw JSON evidence package.");
        sb.AppendLine("- Include chronological timeline and any extortion/ransomware demands.");
        sb.AppendLine("Local Police / Detectives:");
        sb.AppendLine("- Provide printed copy of this document and copy raw evidence to write-protected USB drive.");
        sb.AppendLine("Chain of custody is preserved via SHA-256 digital signature.");
        sb.AppendLine();
        sb.AppendLine(bundle.LegalDisclaimer);

        return sb.ToString();
    }

    public static string GenerateHtmlReport(ForensicEvidenceBundle bundle)
    {
        var coc = bundle.ChainOfCustody;
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"utf-8\">");
        sb.AppendLine("  <title>Downpour Forensic Evidence &amp; Legal Investigation Report</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    :root { --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --crit: #f85149; --high: #ff7b72; --med: #d29922; --low: #3fb950; }");
        sb.AppendLine("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Consolas, monospace; background: var(--bg); color: var(--text); margin: 0; padding: 24px; line-height: 1.5; font-size: 13px; }");
        sb.AppendLine("    .container { max-width: 1200px; margin: 0 auto; }");
        sb.AppendLine("    .header { border-bottom: 2px solid var(--accent); padding-bottom: 16px; margin-bottom: 24px; }");
        sb.AppendLine("    h1 { margin: 0 0 8px 0; font-size: 24px; color: #f0f6fc; }");
        sb.AppendLine("    .subtitle { color: #8b949e; font-size: 14px; }");
        sb.AppendLine("    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 20px; }");
        sb.AppendLine("    .card-title { font-size: 16px; font-weight: 600; color: #58a6ff; margin-bottom: 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }");
        sb.AppendLine("    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }");
        sb.AppendLine("    .metric { background: #21262d; border-radius: 6px; padding: 12px; text-align: center; }");
        sb.AppendLine("    .metric-val { font-size: 22px; font-weight: bold; color: #f0f6fc; }");
        sb.AppendLine("    .metric-lbl { font-size: 11px; color: #8b949e; text-transform: uppercase; margin-top: 4px; }");
        sb.AppendLine("    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }");
        sb.AppendLine("    th, td { border: 1px solid var(--border); padding: 8px 10px; text-align: left; }");
        sb.AppendLine("    th { background: #21262d; color: #8b949e; font-weight: 600; }");
        sb.AppendLine("    tr:nth-child(even) { background: #13171f; }");
        sb.AppendLine("    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-weight: 600; font-size: 11px; }");
        sb.AppendLine("    .badge-CRITICAL { background: #f8514922; color: #ff7b72; border: 1px solid #f85149; }");
        sb.AppendLine("    .badge-HIGH { background: #ff7b7222; color: #ffa657; border: 1px solid #ff7b72; }");
        sb.AppendLine("    .badge-MEDIUM { background: #d2992222; color: #e3b341; border: 1px solid #d29922; }");
        sb.AppendLine("    .badge-LOW { background: #3fb95022; color: #7ee787; border: 1px solid #3fb950; }");
        sb.AppendLine("    .badge-INFORMATIONAL { background: #58a6ff22; color: #79c0ff; border: 1px solid #58a6ff; }");
        sb.AppendLine("    .seal-box { background: #0b1f33; border: 1px solid #1f6feb; border-radius: 6px; padding: 14px; font-family: Consolas, monospace; word-break: break-all; margin: 16px 0; }");
        sb.AppendLine("    .disclaimer { font-size: 11px; color: #8b949e; margin-top: 24px; border-top: 1px solid var(--border); padding-top: 12px; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"container\">");
        sb.AppendLine("    <div class=\"header\">");
        sb.AppendLine("      <h1>DOWNPOUR / FORENSIC EVIDENCE REPORT</h1>");
        sb.AppendLine("      <div class=\"subtitle\">Incident Evidence Package &amp; Digital Forensics Briefing for Law Enforcement (FBI IC3, Police, CERT)</div>");
        sb.AppendLine("    </div>");

        // Metrics Grid
        int critCount = bundle.Artifacts.Count(a => a.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase));
        int highCount = bundle.Artifacts.Count(a => a.Severity.Equals("HIGH", StringComparison.OrdinalIgnoreCase));
        sb.AppendLine("    <div class=\"grid\">");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-val\">{bundle.TotalEvidenceCount}</div><div class=\"metric-lbl\">Total Artifacts</div></div>");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-val\" style=\"color:#ff7b72\">{critCount + highCount}</div><div class=\"metric-lbl\">Critical &amp; High</div></div>");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-val\">{bundle.AttackerIps.Count}</div><div class=\"metric-lbl\">Attacker IPs</div></div>");
        sb.AppendLine($"      <div class=\"metric\"><div class=\"metric-val\">{bundle.SuspiciousPersistenceItems.Count}</div><div class=\"metric-lbl\">Persistence Flags</div></div>");
        sb.AppendLine("    </div>");

        // Chain of Custody & Hash Seal
        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <div class=\"card-title\">Digital Chain of Custody &amp; Integrity Seal</div>");
        sb.AppendLine("      <table>");
        sb.AppendLine($"        <tr><td style=\"width:180px;\"><strong>Hostname</strong></td><td>{coc.Hostname}</td></tr>");
        sb.AppendLine($"        <tr><td><strong>Operating System</strong></td><td>{coc.OsDescription} ({coc.OsArchitecture})</td></tr>");
        sb.AppendLine($"        <tr><td><strong>Local IP Address(es)</strong></td><td>{coc.LocalIpAddresses}</td></tr>");
        sb.AppendLine($"        <tr><td><strong>MAC Address(es)</strong></td><td>{coc.MacAddresses}</td></tr>");
        sb.AppendLine($"        <tr><td><strong>Collector Agent</strong></td><td>{coc.CollectorVersion} (Strictly Read-Only Mode)</td></tr>");
        sb.AppendLine($"        <tr><td><strong>Timestamp (UTC)</strong></td><td>{coc.CollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC</td></tr>");
        sb.AppendLine("      </table>");
        sb.AppendLine("      <div class=\"seal-box\">");
        sb.AppendLine("        <strong style=\"color:#58a6ff;\">SHA-256 DIGITAL EVIDENCE SEAL:</strong><br>");
        sb.AppendLine($"        {coc.EvidenceIntegritySha256}");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // Attacker IPs
        if (bundle.AttackerIps.Count > 0)
        {
            sb.AppendLine("    <div class=\"card\">");
            sb.AppendLine("      <div class=\"card-title\">Attacker &amp; External Indicators (C2 / DDoS / Brute Force)</div>");
            sb.AppendLine("      <table>");
            sb.AppendLine("        <thead><tr><th>Indicator IP</th><th>Classification</th><th>Recommended Action</th></tr></thead>");
            sb.AppendLine("        <tbody>");
            foreach (var ip in bundle.AttackerIps)
            {
                sb.AppendLine($"          <tr><td><code>{ip}</code></td><td>Suspect External Endpoint</td><td>Submit to FBI IC3 / Law Enforcement Evidence Roster</td></tr>");
            }
            sb.AppendLine("        </tbody>");
            sb.AppendLine("      </table>");
            sb.AppendLine("    </div>");
        }

        // Suspicious Persistence
        if (bundle.SuspiciousPersistenceItems.Count > 0)
        {
            sb.AppendLine("    <div class=\"card\">");
            sb.AppendLine("      <div class=\"card-title\">Suspicious Persistence &amp; Autostart Artifacts (T1053.005, T1547.001)</div>");
            sb.AppendLine("      <table>");
            sb.AppendLine("        <thead><tr><th>Artifact</th><th>Assessment</th></tr></thead>");
            sb.AppendLine("        <tbody>");
            foreach (var item in bundle.SuspiciousPersistenceItems)
            {
                sb.AppendLine($"          <tr><td><code>{item}</code></td><td>Suspicious target or script interpreter autostart</td></tr>");
            }
            sb.AppendLine("        </tbody>");
            sb.AppendLine("      </table>");
            sb.AppendLine("    </div>");
        }

        // Evidence Catalog
        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <div class=\"card-title\">Forensic Evidence Catalog</div>");
        sb.AppendLine("      <table>");
        sb.AppendLine("        <thead><tr><th>Severity</th><th>Category</th><th>Technique</th><th>Title &amp; Context</th><th>Timestamp (UTC)</th></tr></thead>");
        sb.AppendLine("        <tbody>");
        foreach (var art in bundle.Artifacts)
        {
            var ts = art.TimestampUtc.HasValue ? art.TimestampUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "N/A";
            var badgeClass = $"badge badge-{art.Severity.ToUpperInvariant()}";
            sb.AppendLine("          <tr>");
            sb.AppendLine($"            <td><span class=\"{badgeClass}\">{art.Severity}</span></td>");
            sb.AppendLine($"            <td>{art.Category}</td>");
            sb.AppendLine($"            <td><code>{art.Technique ?? "—"}</code></td>");
            sb.AppendLine($"            <td><strong>{art.Title}</strong><br><small style=\"color:#8b949e;\">{art.Detail}</small></td>");
            sb.AppendLine($"            <td>{ts}</td>");
            sb.AppendLine("          </tr>");
        }
        sb.AppendLine("        </tbody>");
        sb.AppendLine("      </table>");
        sb.AppendLine("    </div>");

        // Law Enforcement Filing Guidance
        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <div class=\"card-title\">Law Enforcement &amp; Legal Filing Instructions</div>");
        sb.AppendLine("      <p><strong>FBI Internet Crime Complaint Center (IC3):</strong> File online at <a href=\"https://www.ic3.gov\" target=\"_blank\" style=\"color:#58a6ff;\">https://www.ic3.gov</a>. Attach this generated HTML report and the raw JSON evidence bundle to your complaint filing.</p>");
        sb.AppendLine("      <p><strong>Local Police Department / Detective Bureau:</strong> Print this document in full. Provide the accompanying write-protected USB storage media containing the raw cryptographic JSON bundle. State that the evidence was gathered passively without altering the target system.</p>");
        sb.AppendLine("      <p><strong>National CERT / CISA:</strong> Forward this report to relevant national computer emergency response teams if critical infrastructure or advanced persistent threats are suspected.</p>");
        sb.AppendLine("    </div>");

        // Footer disclaimer
        sb.AppendLine($"    <div class=\"disclaimer\">{bundle.LegalDisclaimer}</div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }
}
