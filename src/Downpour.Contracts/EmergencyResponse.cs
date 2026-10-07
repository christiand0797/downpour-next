namespace Downpour.Contracts;

/// <summary>
/// Status and metadata for a process captured during an emergency snapshot or incident.
/// </summary>
public sealed record EmergencyProcessInfo(
    int ProcessId,
    string ProcessName,
    string ExecutablePath,
    long WorkingSetBytes,
    DateTimeOffset? StartTimeUtc,
    bool IsSuspicious,
    string SuspicionReason,
    string MitreTechnique);

/// <summary>
/// Active network connection captured during emergency containment.
/// </summary>
public sealed record EmergencyConnectionInfo(
    string LocalEndpoint,
    string RemoteEndpoint,
    string State,
    int OwningProcessId,
    string OwningProcessName);

/// <summary>
/// Point-in-time system snapshot for forensic evidence and incident response.
/// </summary>
public sealed record EmergencySnapshot(
    string SnapshotId,
    DateTimeOffset TimestampUtc,
    string MachineName,
    string OsVersion,
    int ProcessCount,
    int ConnectionCount,
    int SuspiciousProcessCount,
    IReadOnlyList<EmergencyProcessInfo> Processes,
    IReadOnlyList<EmergencyConnectionInfo> Connections,
    string ForensicSealSha256,
    string SnapshotFilePath);

/// <summary>
/// Severity of an emergency event log entry.
/// </summary>
public enum EmergencyLogSeverity
{
    Info,
    Success,
    Warning,
    Critical
}

/// <summary>
/// Structured log entry for emergency response actions.
/// </summary>
public sealed record EmergencyLogEntry(
    DateTimeOffset TimestampUtc,
    EmergencyLogSeverity Severity,
    string ActionName,
    string Message);

/// <summary>
/// Types of emergency response actions available.
/// </summary>
public enum EmergencyActionType
{
    FullLockdown,
    SystemSnapshot,
    IsolateNetwork,
    RestoreNetwork,
    TerminateSuspicious,
    CollectForensics,
    ExportIrReport,
    LockWorkstation
}

/// <summary>
/// Status of an emergency containment action execution.
/// </summary>
public enum EmergencyActionStatus
{
    Completed,
    GuardedPendingAuthorization,
    Failed,
    Skipped
}

/// <summary>
/// Execution result of an emergency response action.
/// </summary>
public sealed record EmergencyActionResult(
    EmergencyActionType ActionType,
    EmergencyActionStatus Status,
    string ActionTitle,
    string Details,
    bool RequiresActionBroker,
    DateTimeOffset ExecutedAtUtc);

/// <summary>
/// Outcome summary of a full emergency lockdown procedure.
/// </summary>
public sealed record EmergencyLockdownOutcome(
    string ResponseId,
    DateTimeOffset TimestampUtc,
    IReadOnlyList<EmergencyActionResult> ActionResults,
    string? SnapshotPath,
    int SuspiciousProcessesCount,
    string Summary);
