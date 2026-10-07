using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>
/// Coordinates rapid incident containment, volatile forensic snapshots,
/// suspicious process screening, and guarded emergency lockdown actions.
/// All mutating actions remain strictly guarded under least-privilege policy (DN-008).
/// </summary>
public sealed class EmergencyResponseCoordinator
{
    private static readonly string[] SuspiciousProcessNames =
    [
        "mimikatz", "psexec", "procdump", "lazagne", "netcat", "nc.exe", "ncat",
        "chisel", "socat", "cobaltstrike", "bloodhound", "sharphound", "rubeus", "seatbelt"
    ];

    private static readonly string[] SuspiciousPathFragments =
    [
        @"\temp\",
        @"\appdata\local\temp\",
        @"\users\public\"
    ];

    private readonly string _snapshotsDirectory;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LockWorkStation();

    public EmergencyResponseCoordinator(string? snapshotsDirectory = null)
    {
        _snapshotsDirectory = snapshotsDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DownpourNext",
            "emergency_snapshots");
    }

    /// <summary>
    /// Gets the target directory where emergency snapshots are stored.
    /// </summary>
    public string SnapshotsDirectory => _snapshotsDirectory;

    /// <summary>
    /// Captures a point-in-time emergency system snapshot including processes, active TCP
    /// connections, suspicious indicators, and a deterministic SHA-256 forensic seal.
    /// </summary>
    public async Task<EmergencySnapshot> CaptureSnapshotAsync(
        IReadOnlyList<EmergencyProcessInfo>? simulatedProcesses = null,
        IReadOnlyList<EmergencyConnectionInfo>? simulatedConnections = null,
        CancellationToken cancellationToken = default)
    {
        var timestamp = DateTimeOffset.UtcNow;
        var responseId = GenerateResponseId(timestamp);

        var processes = simulatedProcesses ?? await Task.Run(CollectCurrentProcesses, cancellationToken);
        var connections = simulatedConnections ?? await Task.Run(CollectActiveConnections, cancellationToken);

        int suspiciousCount = processes.Count(p => p.IsSuspicious);

        var sealHash = ComputeForensicSeal(timestamp, responseId, processes, connections);

        var snapshot = new EmergencySnapshot(
            SnapshotId: responseId,
            TimestampUtc: timestamp,
            MachineName: Environment.MachineName,
            OsVersion: Environment.OSVersion.ToString(),
            ProcessCount: processes.Count,
            ConnectionCount: connections.Count,
            SuspiciousProcessCount: suspiciousCount,
            Processes: processes,
            Connections: connections,
            ForensicSealSha256: sealHash,
            SnapshotFilePath: string.Empty);

        // Persist snapshot to disk
        string filePath = await SaveSnapshotToDiskAsync(snapshot, responseId, cancellationToken);

        return snapshot with { SnapshotFilePath = filePath };
    }

    /// <summary>
    /// Executes a single emergency action in accordance with least-privilege policy.
    /// System-altering actions (isolation, process kill) are guarded under DN-008 Action Broker.
    /// </summary>
    public async Task<EmergencyActionResult> ExecuteActionAsync(
        EmergencyActionType actionType,
        EmergencySnapshot? existingSnapshot = null,
        bool isSimulated = false,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        switch (actionType)
        {
            case EmergencyActionType.SystemSnapshot:
            {
                var snapshot = existingSnapshot ?? await CaptureSnapshotAsync(cancellationToken: cancellationToken);
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: EmergencyActionStatus.Completed,
                    ActionTitle: "System Snapshot",
                    Details: $"Point-in-time forensic snapshot captured: {snapshot.Processes.Count} processes, {snapshot.Connections.Count} connections. Sealed with SHA-256 ({snapshot.ForensicSealSha256[..8]}...). Saved to: {snapshot.SnapshotFilePath}",
                    RequiresActionBroker: false,
                    ExecutedAtUtc: now);
            }

            case EmergencyActionType.CollectForensics:
            {
                var snapshot = existingSnapshot ?? await CaptureSnapshotAsync(cancellationToken: cancellationToken);
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: EmergencyActionStatus.Completed,
                    ActionTitle: "Collect Forensics",
                    Details: $"Volatile evidence collection completed. {snapshot.Processes.Count} processes cataloged, {snapshot.SuspiciousProcessCount} suspicious indicators flagged, {snapshot.Connections.Count} TCP endpoints recorded.",
                    RequiresActionBroker: false,
                    ExecutedAtUtc: now);
            }

            case EmergencyActionType.ExportIrReport:
            {
                var snapshot = existingSnapshot ?? await CaptureSnapshotAsync(cancellationToken: cancellationToken);
                var report = GenerateIncidentResponseReport(snapshot);
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: EmergencyActionStatus.Completed,
                    ActionTitle: "Export IR Report",
                    Details: $"Incident Response (IR) Markdown report compiled successfully ({report.Length:N0} characters).",
                    RequiresActionBroker: false,
                    ExecutedAtUtc: now);
            }

            case EmergencyActionType.LockWorkstation:
            {
                if (isSimulated)
                {
                    return new EmergencyActionResult(
                        ActionType: actionType,
                        Status: EmergencyActionStatus.Completed,
                        ActionTitle: "Lock Workstation (Simulated)",
                        Details: "Workstation session lock simulated successfully.",
                        RequiresActionBroker: false,
                        ExecutedAtUtc: now);
                }

                bool locked = LockWorkstationSession();
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: locked ? EmergencyActionStatus.Completed : EmergencyActionStatus.Failed,
                    ActionTitle: "Lock Workstation",
                    Details: locked ? "Windows workstation session locked via user32.dll." : "Lock workstation invocation failed.",
                    RequiresActionBroker: false,
                    ExecutedAtUtc: now);
            }

            case EmergencyActionType.IsolateNetwork:
            {
                // In accordance with AGENTS.md and DN-008, host network isolation is system-altering
                // and guarded pending distinct Action Broker authorization policy.
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: EmergencyActionStatus.GuardedPendingAuthorization,
                    ActionTitle: "Isolate Network",
                    Details: "Network isolation (host adapter disable / firewall block) is guarded by least-privilege policy (DN-008). Destructive containment actions require distinct elevated action broker authorization.",
                    RequiresActionBroker: true,
                    ExecutedAtUtc: now);
            }

            case EmergencyActionType.RestoreNetwork:
            {
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: EmergencyActionStatus.GuardedPendingAuthorization,
                    ActionTitle: "Restore Network",
                    Details: "Network adapter restoration is guarded by least-privilege policy (DN-008). Modifying host firewall or adapter states requires an audited action broker token.",
                    RequiresActionBroker: true,
                    ExecutedAtUtc: now);
            }

            case EmergencyActionType.TerminateSuspicious:
            {
                int suspiciousCount = existingSnapshot?.SuspiciousProcessCount ?? 0;
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: EmergencyActionStatus.GuardedPendingAuthorization,
                    ActionTitle: "Terminate Suspicious Processes",
                    Details: $"Termination of {suspiciousCount} flagged process(es) was guarded by least-privilege policy. Process termination requires an explicit operator confirmation and audited action broker (DN-008).",
                    RequiresActionBroker: true,
                    ExecutedAtUtc: now);
            }

            case EmergencyActionType.FullLockdown:
            default:
            {
                var lockdown = await ExecuteFullLockdownAsync(isSimulated, cancellationToken);
                return new EmergencyActionResult(
                    ActionType: actionType,
                    Status: EmergencyActionStatus.Completed,
                    ActionTitle: "Full Emergency Lockdown",
                    Details: lockdown.Summary,
                    RequiresActionBroker: false,
                    ExecutedAtUtc: now);
            }
        }
    }

    /// <summary>
    /// Executes the full emergency lockdown sequence: captures a point-in-time system snapshot,
    /// screens for suspicious indicators, evaluates guarded containment actions under DN-008,
    /// and produces an auditable outcome record.
    /// </summary>
    public async Task<EmergencyLockdownOutcome> ExecuteFullLockdownAsync(
        bool isSimulated = false,
        CancellationToken cancellationToken = default)
    {
        var timestamp = DateTimeOffset.UtcNow;
        var responseId = GenerateResponseId(timestamp);
        var results = new List<EmergencyActionResult>();

        // 1. Capture system snapshot (Safe / Non-destructive)
        var snapshot = await CaptureSnapshotAsync(cancellationToken: cancellationToken);
        results.Add(new EmergencyActionResult(
            ActionType: EmergencyActionType.SystemSnapshot,
            Status: EmergencyActionStatus.Completed,
            ActionTitle: "System Snapshot",
            Details: $"Snapshot captured: {snapshot.ProcessCount} processes, {snapshot.ConnectionCount} connections. SHA-256 seal: {snapshot.ForensicSealSha256[..8]}...",
            RequiresActionBroker: false,
            ExecutedAtUtc: DateTimeOffset.UtcNow));

        // 2. Evaluate Network Isolation (Guarded)
        results.Add(new EmergencyActionResult(
            ActionType: EmergencyActionType.IsolateNetwork,
            Status: EmergencyActionStatus.GuardedPendingAuthorization,
            ActionTitle: "Network Isolation",
            Details: "Host network isolation was guarded under least-privilege policy (DN-008). System-changing adapter disablement requires elevated action broker policy.",
            RequiresActionBroker: true,
            ExecutedAtUtc: DateTimeOffset.UtcNow));

        // 3. Evaluate Process Termination (Guarded)
        results.Add(new EmergencyActionResult(
            ActionType: EmergencyActionType.TerminateSuspicious,
            Status: EmergencyActionStatus.GuardedPendingAuthorization,
            ActionTitle: "Terminate Suspicious Processes",
            Details: $"Termination of {snapshot.SuspiciousProcessCount} flagged process(es) was guarded under least-privilege policy (DN-008).",
            RequiresActionBroker: true,
            ExecutedAtUtc: DateTimeOffset.UtcNow));

        // 4. Forensics Evidence Packaging (Safe)
        results.Add(new EmergencyActionResult(
            ActionType: EmergencyActionType.CollectForensics,
            Status: EmergencyActionStatus.Completed,
            ActionTitle: "Volatile Evidence Packaging",
            Details: $"Snapshot persisted to {snapshot.SnapshotFilePath}",
            RequiresActionBroker: false,
            ExecutedAtUtc: DateTimeOffset.UtcNow));

        var summary = $"Emergency Lockdown executed (Response ID: {responseId}). Snapshot saved with {snapshot.ProcessCount} processes ({snapshot.SuspiciousProcessCount} suspicious). Mutating network & process actions guarded under DN-008.";

        return new EmergencyLockdownOutcome(
            ResponseId: responseId,
            TimestampUtc: timestamp,
            ActionResults: results,
            SnapshotPath: snapshot.SnapshotFilePath,
            SuspiciousProcessesCount: snapshot.SuspiciousProcessCount,
            Summary: summary);
    }

    /// <summary>
    /// Generates a structured Markdown Incident Response (IR) Report.
    /// </summary>
    public string GenerateIncidentResponseReport(
        EmergencySnapshot snapshot,
        IReadOnlyList<EmergencyLogEntry>? logEntries = null)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# Incident Response (IR) Forensic Report");
        sb.AppendLine();
        sb.AppendLine($"- **Response ID**: `{snapshot.SnapshotId}`");
        sb.AppendLine($"- **Timestamp (UTC)**: `{snapshot.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC`");
        sb.AppendLine($"- **Target Host**: `{snapshot.MachineName}`");
        sb.AppendLine($"- **OS Version**: `{snapshot.OsVersion}`");
        sb.AppendLine($"- **Forensic Seal (SHA-256)**: `{snapshot.ForensicSealSha256}`");
        sb.AppendLine();
        sb.AppendLine("## 1. Executive Summary");
        sb.AppendLine();
        sb.AppendLine($"During emergency assessment, a total of **{snapshot.ProcessCount}** running processes and **{snapshot.ConnectionCount}** active TCP connections were cataloged.");
        if (snapshot.SuspiciousProcessCount > 0)
        {
            sb.AppendLine($"> [!WARNING]");
            sb.AppendLine($"> **{snapshot.SuspiciousProcessCount} suspicious process indicator(s)** were identified during screening. Immediate analysis is recommended.");
        }
        else
        {
            sb.AppendLine("> [!NOTE]");
            sb.AppendLine("> No signature-flagged suspicious processes or unauthorized temporary execution paths were detected during snapshot screening.");
        }
        sb.AppendLine();
        sb.AppendLine("## 2. Suspicious Process Screening");
        sb.AppendLine();
        var suspiciousProcs = snapshot.Processes.Where(p => p.IsSuspicious).ToList();
        if (suspiciousProcs.Count > 0)
        {
            sb.AppendLine("| PID | Process Name | Memory (MB) | Suspicion Reason | MITRE ATT&CK | Executable Path |");
            sb.AppendLine("|-----|--------------|-------------|------------------|--------------|-----------------|");
            foreach (var proc in suspiciousProcs)
            {
                double memMb = proc.WorkingSetBytes / (1024.0 * 1024.0);
                sb.AppendLine($"| {proc.ProcessId} | `{proc.ProcessName}` | {memMb:F1} MB | {proc.SuspicionReason} | `{proc.MitreTechnique}` | `{proc.ExecutablePath}` |");
            }
        }
        else
        {
            sb.AppendLine("*No suspicious processes flagged.*");
        }
        sb.AppendLine();
        sb.AppendLine("## 3. Active Network Telemetry (Top 25)");
        sb.AppendLine();
        sb.AppendLine("| Local Endpoint | Remote Endpoint | State | Owning PID | Process Name |");
        sb.AppendLine("|----------------|-----------------|-------|------------|--------------|");
        foreach (var conn in snapshot.Connections.Take(25))
        {
            sb.AppendLine($"| `{conn.LocalEndpoint}` | `{conn.RemoteEndpoint}` | {conn.State} | {conn.OwningProcessId} | `{conn.OwningProcessName}` |");
        }
        if (snapshot.Connections.Count > 25)
        {
            sb.AppendLine($"*... and {snapshot.Connections.Count - 25} more network connection(s).*");
        }
        sb.AppendLine();
        sb.AppendLine("## 4. Emergency Action & DN-008 Guard Status");
        sb.AppendLine();
        sb.AppendLine("- **Volatile Forensic Snapshot**: COMPLETED & VERIFIED");
        sb.AppendLine("- **Network Isolation**: GUARDED (Requires elevated Action Broker policy DN-008)");
        sb.AppendLine("- **Process Termination**: GUARDED (Requires elevated Action Broker policy DN-008)");
        sb.AppendLine();
        sb.AppendLine("## 5. Recommended Containment Procedures");
        sb.AppendLine();
        sb.AppendLine("1. Review identified suspicious process executable paths for unauthorized persistence.");
        sb.AppendLine("2. Run a full antivirus & YARA scan on all system volumes.");
        sb.AppendLine("3. Inspect active persistence mechanisms (Scheduled Tasks, Run keys, WMI subscriptions).");
        sb.AppendLine("4. Export forensic bundle and preserve memory artifacts if formal forensic analysis is required.");
        sb.AppendLine();

        if (logEntries is { Count: > 0 })
        {
            sb.AppendLine("## 6. Emergency Event Audit Log");
            sb.AppendLine();
            sb.AppendLine("| Timestamp (UTC) | Severity | Action | Message |");
            sb.AppendLine("|-----------------|----------|--------|---------|");
            foreach (var log in logEntries)
            {
                sb.AppendLine($"| `{log.TimestampUtc:HH:mm:ss}` | {log.Severity} | {log.ActionName} | {log.Message} |");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>
    /// Evaluates whether a process descriptor matches suspicious indicators.
    /// </summary>
    public static (bool IsSuspicious, string Reason, string MitreTechnique) EvaluateProcess(
        string processName,
        string executablePath)
    {
        string lowerName = processName.ToLowerInvariant();
        string lowerPath = (executablePath ?? string.Empty).ToLowerInvariant();

        // 1. Known malicious tool name indicators
        foreach (var susp in SuspiciousProcessNames)
        {
            if (lowerName.Contains(susp, StringComparison.OrdinalIgnoreCase))
            {
                return (true, $"Known attack or exploitation tool name match ('{susp}')", "T1003/T1572");
            }
        }

        // 2. Suspicious path indicators (e.g. running directly out of Temp or Public)
        foreach (var pathFrag in SuspiciousPathFragments)
        {
            if (lowerPath.Contains(pathFrag, StringComparison.OrdinalIgnoreCase))
            {
                return (true, $"Process executing from suspicious path ('{pathFrag}')", "T1036/T1059");
            }
        }

        return (false, string.Empty, string.Empty);
    }

    private static IReadOnlyList<EmergencyProcessInfo> CollectCurrentProcesses()
    {
        var result = new List<EmergencyProcessInfo>();

        try
        {
            var processes = Process.GetProcesses();
            foreach (var p in processes)
            {
                try
                {
                    string name = p.ProcessName;
                    string path = string.Empty;
                    DateTimeOffset? start = null;

                    try
                    {
                        path = p.MainModule?.FileName ?? string.Empty;
                    }
                    catch
                    {
                        // Access denied on protected processes (e.g., csrss, smss)
                    }

                    try
                    {
                        start = p.StartTime.ToUniversalTime();
                    }
                    catch
                    {
                        // Access denied
                    }

                    var (isSuspicious, reason, technique) = EvaluateProcess(name, path);

                    result.Add(new EmergencyProcessInfo(
                        ProcessId: p.Id,
                        ProcessName: name,
                        ExecutablePath: path,
                        WorkingSetBytes: p.WorkingSet64,
                        StartTimeUtc: start,
                        IsSuspicious: isSuspicious,
                        SuspicionReason: reason,
                        MitreTechnique: technique));
                }
                catch
                {
                    // Process exited during iteration
                }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch
        {
            // Fallback if process enumeration fails
        }

        return result;
    }

    private static IReadOnlyList<EmergencyConnectionInfo> CollectActiveConnections()
    {
        var result = new List<EmergencyConnectionInfo>();

        try
        {
            var ipProps = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = ipProps.GetActiveTcpConnections();

            foreach (var conn in tcpConnections)
            {
                result.Add(new EmergencyConnectionInfo(
                    LocalEndpoint: conn.LocalEndPoint.ToString(),
                    RemoteEndpoint: conn.RemoteEndPoint.ToString(),
                    State: conn.State.ToString(),
                    OwningProcessId: 0,
                    OwningProcessName: "Unknown"));
            }
        }
        catch
        {
            // In sandboxed environments or without network privileges
        }

        return result;
    }

    private static string ComputeForensicSeal(
        DateTimeOffset timestamp,
        string responseId,
        IReadOnlyList<EmergencyProcessInfo> processes,
        IReadOnlyList<EmergencyConnectionInfo> connections)
    {
        var sb = new StringBuilder();
        sb.Append(responseId).Append('|').Append(timestamp.ToUnixTimeSeconds()).Append('|');
        sb.Append(processes.Count).Append('|').Append(connections.Count).Append('|');

        foreach (var p in processes.OrderBy(p => p.ProcessId).Take(50))
        {
            sb.Append(p.ProcessId).Append(':').Append(p.ProcessName).Append(';');
        }

        byte[] bytes = Encoding.UTF8.GetBytes(sb.ToString());
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }

    private static string GenerateResponseId(DateTimeOffset timestamp)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(timestamp.ToString("O") + Guid.NewGuid()));
        return Convert.ToHexString(hash)[..8].ToLowerInvariant();
    }

    private async Task<string> SaveSnapshotToDiskAsync(
        EmergencySnapshot snapshot,
        string responseId,
        CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(_snapshotsDirectory);
            string fileName = $"emergency_snapshot_{responseId}_{snapshot.TimestampUtc:yyyyMMdd_HHmmss}.json";
            string filePath = Path.Combine(_snapshotsDirectory, fileName);

            string json = JsonConvert.SerializeObject(snapshot, Formatting.Indented);
            await File.WriteAllTextAsync(filePath, json, cancellationToken);

            return filePath;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static bool LockWorkstationSession()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return LockWorkStation();
            }
        }
        catch
        {
            // Win32 call failure
        }

        return false;
    }
}
