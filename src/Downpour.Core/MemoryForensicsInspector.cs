using System.Diagnostics;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed record ProcessDescriptor(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath,
    long WorkingSetBytes,
    int ThreadCount);

public static class MemoryForensicsInspector
{
    private const int MaxProcessesToScan = 512;

    private static readonly HashSet<string> CoreSystemBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "winlogon.exe", "wininit.exe"
    };

    private static readonly HashSet<string> TypoSquattedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svch0st.exe", "scvhost.exe", "svchosts.exe", "lsas.exe", "lsassa.exe",
        "csrs.exe", "win1ogon.exe", "taskmngr.exe", "explorerr.exe", "rundl132.exe"
    };

    public static async Task<MemoryForensicsSummary> ScanAsync(
        SecurityAlertClient? alertClient = null,
        IReadOnlyList<ProcessDescriptor>? simulatedProcesses = null,
        CancellationToken cancellationToken = default)
    {
        var descriptors = simulatedProcesses ?? GetCurrentProcessDescriptors();
        var alertMap = await LoadAlertsAsync(alertClient, cancellationToken);

        var inspections = new List<ProcessMemoryInspection>(descriptors.Count);

        foreach (var desc in descriptors.Take(MaxProcessesToScan))
        {
            if (cancellationToken.IsCancellationRequested) break;
            var inspection = InspectProcess(desc, alertMap);
            inspections.Add(inspection);
        }

        var sorted = inspections
            .OrderByDescending(i => i.InjectionScore)
            .ThenByDescending(i => i.WorkingSetBytes)
            .ToList();

        var highRisk = sorted.Where(i => i.InjectionScore >= 20).ToList();
        int injected = sorted.Count(i => i.Classification == "Injected");
        int suspicious = sorted.Count(i => i.Classification == "Suspicious");
        int clean = sorted.Count(i => i.Classification == "Clean");

        const string notice = "Process termination and volatile memory dumping are guarded under least-privilege security policy. Terminating processes requires an audited action broker (DN-008). Passive memory inspection and injection pattern scoring are active.";

        return new MemoryForensicsSummary(
            TotalProcessesScanned: sorted.Count,
            InjectedCount: injected,
            SuspiciousCount: suspicious,
            CleanCount: clean,
            HighRiskProcesses: highRisk,
            AllInspections: sorted,
            InspectedAtUtc: DateTimeOffset.UtcNow,
            SecurityNotice: notice);
    }

    public static ProcessMemoryInspection InspectProcess(
        ProcessDescriptor proc,
        IReadOnlyDictionary<int, List<SecurityAlert>>? alertMap = null)
    {
        int score = 0;
        var findings = new List<string>();
        string suspectedTech = "None";

        var nameWithExt = proc.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? proc.ProcessName
            : $"{proc.ProcessName}.exe";

        // 1. Typo-squatting / Process Masquerading Name Check (T1036)
        if (TypoSquattedNames.Contains(nameWithExt))
        {
            score += 35;
            findings.Add($"Typo-squatted process name detected ('{proc.ProcessName}') masquerading as Windows system component (T1036)");
            suspectedTech = "T1036 Process Masquerading";
        }

        // 2. Core System Binary Path Validation (T1036.005)
        if (CoreSystemBinaries.Contains(nameWithExt) && !string.IsNullOrWhiteSpace(proc.ExecutablePath))
        {
            var lowerPath = proc.ExecutablePath.ToLowerInvariant();
            var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32").ToLowerInvariant();

            if (!lowerPath.StartsWith(system32, StringComparison.OrdinalIgnoreCase))
            {
                score += 50;
                findings.Add($"Core system binary '{proc.ProcessName}' is running outside System32: '{proc.ExecutablePath}' (Process Masquerading T1036.005)");
                suspectedTech = "T1036.005 Masquerading: Core Binary Outside System32";
            }
        }

        // 3. Temporary / User Writable Execution Directory Check (T1059 / T1204)
        if (!string.IsNullOrWhiteSpace(proc.ExecutablePath))
        {
            var lowerPath = proc.ExecutablePath.ToLowerInvariant();
            if (lowerPath.Contains(@"\temp\") ||
                lowerPath.Contains(@"\appdata\local\temp\") ||
                lowerPath.Contains(@"\users\") && lowerPath.Contains(@"\downloads\"))
            {
                score += 25;
                findings.Add($"Process binary is executing from user temporary or download directory: '{proc.ExecutablePath}'");
                if (suspectedTech == "None") suspectedTech = "T1204 User Execution / Temp Path";
            }
        }

        // 4. Unusual Thread Count Checks
        if (proc.ThreadCount == 1 && !string.IsNullOrWhiteSpace(proc.ExecutablePath) && proc.WorkingSetBytes > 50L * 1024 * 1024)
        {
            score += 15;
            findings.Add($"Single thread execution with unusually large memory footprint ({proc.WorkingSetBytes / 1024 / 1024} MiB)");
        }

        // 5. Correlate with Security Alerts for Process Injection (T1055)
        if (alertMap is not null && alertMap.TryGetValue(proc.ProcessId, out var alerts))
        {
            foreach (var alert in alerts)
            {
                var tech = alert.Technique ?? string.Empty;
                var title = alert.Title ?? string.Empty;
                var combined = $"{title} {tech}";

                if (combined.Contains("1055", StringComparison.OrdinalIgnoreCase) ||
                    combined.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                    combined.Contains("remotethread", StringComparison.OrdinalIgnoreCase))
                {
                    score += 45;
                    findings.Add($"Active security alert flags process injection: {alert.Title} ({alert.Technique})");
                    suspectedTech = "T1055 Process Injection";
                }
                else if (combined.Contains("1003", StringComparison.OrdinalIgnoreCase) ||
                         combined.Contains("lsass", StringComparison.OrdinalIgnoreCase))
                {
                    score += 40;
                    findings.Add($"Security alert flags credential dumping / LSASS access: {alert.Title}");
                    suspectedTech = "T1003 OS Credential Dumping";
                }
            }
        }

        // 6. Classification & Severity
        score = Math.Clamp(score, 0, 100);

        string classification;
        string severity;

        if (score >= 50)
        {
            classification = "Injected";
            severity = score >= 75 ? "CRITICAL" : "HIGH";
        }
        else if (score >= 20)
        {
            classification = "Suspicious";
            severity = score >= 35 ? "HIGH" : "MEDIUM";
        }
        else
        {
            classification = "Clean";
            severity = "CLEAN";
        }

        return new ProcessMemoryInspection(
            ProcessId: proc.ProcessId,
            ProcessName: proc.ProcessName,
            ExecutablePath: proc.ExecutablePath ?? "Unknown / Protected",
            WorkingSetBytes: proc.WorkingSetBytes,
            ThreadCount: proc.ThreadCount,
            InjectionScore: score,
            Classification: classification,
            Severity: severity,
            Findings: findings,
            SuspectedTechnique: suspectedTech);
    }

    private static IReadOnlyList<ProcessDescriptor> GetCurrentProcessDescriptors()
    {
        var list = new List<ProcessDescriptor>();
        try
        {
            var processes = Process.GetProcesses();
            foreach (var p in processes)
            {
                try
                {
                    string? path = null;
                    try
                    {
                        path = p.MainModule?.FileName;
                    }
                    catch
                    {
                        // Inaccessible process module (e.g. system/protected process)
                    }

                    list.Add(new ProcessDescriptor(
                        ProcessId: p.Id,
                        ProcessName: p.ProcessName,
                        ExecutablePath: path,
                        WorkingSetBytes: p.WorkingSet64,
                        ThreadCount: p.Threads.Count));
                }
                catch
                {
                    // Ignore process that terminated during enumeration
                }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch
        {
            // Process enumeration fallback
        }

        return list;
    }

    private static async Task<Dictionary<int, List<SecurityAlert>>> LoadAlertsAsync(
        SecurityAlertClient? alertClient,
        CancellationToken cancellationToken)
    {
        var map = new Dictionary<int, List<SecurityAlert>>();
        try
        {
            var client = alertClient ?? new SecurityAlertClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var snapshot = await client.TryGetSnapshotAsync(cts.Token);
            if (snapshot is not null)
            {
                foreach (var alert in snapshot.Alerts)
                {
                    if (int.TryParse(alert.AlertId, out var pid))
                    {
                        if (!map.TryGetValue(pid, out var list))
                        {
                            list = [];
                            map[pid] = list;
                        }
                        list.Add(alert);
                    }
                }
            }
        }
        catch
        {
            // Offline sensor alert query ignored
        }
        return map;
    }

    public static string GenerateReport(MemoryForensicsSummary summary)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== DOWNPOUR MEMORY FORENSICS & INJECTION REPORT ===");
        sb.AppendLine($"Timestamp:         {summary.InspectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Processes Scanned: {summary.TotalProcessesScanned:N0}");
        sb.AppendLine($"Injected (Alert):  {summary.InjectedCount}");
        sb.AppendLine($"Suspicious:        {summary.SuspiciousCount}");
        sb.AppendLine($"Clean:             {summary.CleanCount}");
        sb.AppendLine();

        sb.AppendLine($"=== HIGH-RISK PROCESSES & INJECTION FINDINGS ({summary.HighRiskProcesses.Count}) ===");
        if (summary.HighRiskProcesses.Count == 0)
        {
            sb.AppendLine("  No process injection, masquerading, or memory anomalies detected.");
        }
        else
        {
            foreach (var proc in summary.HighRiskProcesses)
            {
                sb.AppendLine($"  [{proc.Severity}] [{proc.Classification}] PID {proc.ProcessId}: {proc.ProcessName} (Score: {proc.InjectionScore}/100)");
                sb.AppendLine($"     Path:      {proc.ExecutablePath}");
                sb.AppendLine($"     Technique: {proc.SuspectedTechnique}");
                sb.AppendLine($"     Memory:    {proc.WorkingSetBytes / 1024.0 / 1024.0:F1} MiB | Threads: {proc.ThreadCount}");
                foreach (var f in proc.Findings)
                {
                    sb.AppendLine($"     - {f}");
                }
                sb.AppendLine();
            }
        }

        sb.AppendLine("=== SAFETY & EXECUTION POLICY NOTICE ===");
        sb.AppendLine(summary.SecurityNotice);

        return sb.ToString();
    }
}
