namespace Downpour.Contracts;

public sealed record ServiceHealthSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string ServiceState,
    string OperatingMode,
    IReadOnlyList<string> ConnectedSensors,
    IReadOnlyList<string> Warnings);

public sealed record ProcessSnapshot(int ProcessId, string Name, long WorkingSetBytes, int ThreadCount, double? CpuPercent = null);

public sealed record SystemHealthSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    int ProcessCount,
    double? CpuPercent,
    ulong MemoryTotalBytes,
    ulong MemoryAvailableBytes,
    int? ActiveTcpConnections,
    IReadOnlyList<ProcessSnapshot> TopProcesses,
    IReadOnlyList<string> Warnings,
    ulong? MemoryCommitLimitBytes = null,
    ulong? MemoryCommittedBytes = null,
    long? DiskReadBytesPerSecond = null,
    long? DiskWriteBytesPerSecond = null,
    IReadOnlyList<double?>? PerCoreCpuPercent = null,
    ulong? PageFileTotalBytes = null,
    ulong? PageFileAvailableBytes = null,
    IReadOnlyList<PhysicalDiskSnapshot>? PhysicalDisks = null);

public sealed record PhysicalDiskSnapshot(
    string InstanceName,
    long? ReadBytesPerSecond,
    long? WriteBytesPerSecond);

public sealed record DriverInventoryEntry(string Name, string ImagePath, bool IsUnderSystemDrivers, bool IsInUserWritableLocation);

public sealed record DriverInventorySnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    int DriverCount,
    IReadOnlyList<DriverInventoryEntry> Drivers,
    IReadOnlyList<string> Warnings);

public sealed record WindowsServiceInventoryEntry(
    string ServiceName,
    string DisplayName,
    string State,
    string StartupType,
    string ImagePath = "",
    string Risk = "Clean",
    IReadOnlyList<string>? RiskIndicators = null);

public sealed record WindowsServiceInventorySnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string CollectionStatus,
    int ServiceCount,
    IReadOnlyList<WindowsServiceInventoryEntry> Services,
    IReadOnlyList<string> Warnings);

public sealed record InstalledSoftwareEntry(string Name, string Version, string Publisher, string RegistryScope);

public sealed record InstalledSoftwareSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string CollectionStatus,
    int TotalCount,
    IReadOnlyList<InstalledSoftwareEntry> Software,
    IReadOnlyList<string> Warnings);

public sealed record NetworkInterfaceEntry(
    string Name,
    string Description,
    string Status,
    long? ReceiveBytesPerSecond,
    long? SendBytesPerSecond,
    long TotalReceivedBytes,
    long TotalSentBytes);

public sealed record NetworkConnectionEntry(
    string LocalEndpoint,
    string RemoteEndpoint,
    string State);

public sealed record NetworkInventorySnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<NetworkInterfaceEntry> Interfaces,
    IReadOnlyList<NetworkConnectionEntry> Connections,
    int TotalConnectionCount,
    IReadOnlyList<string> Warnings);

public sealed record SecurityEventObservation(
    string LogName,
    string Provider,
    int EventId,
    long? RecordId,
    DateTimeOffset? CreatedAtUtc,
    string Severity,
    string Technique,
    string Summary,
    int Occurrences = 1);

public sealed record SecurityEventSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<SecurityEventObservation> Events,
    int SourcesQueried,
    IReadOnlyList<string> Warnings);

public sealed record SecurityAlert(
    string AlertId,
    string Title,
    string Severity,
    string Technique,
    string LogName,
    string Provider,
    int EventId,
    long? RecordId,
    DateTimeOffset EventTimeUtc,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int Occurrences,
    string State,
    bool IsVerified = false);

public sealed record SecurityAlertSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    int TotalCount,
    IReadOnlyList<SecurityAlert> Alerts,
    IReadOnlyList<string> Warnings);

public sealed record AlertStateChangeRequest(int SchemaVersion, Guid RequestId, string AlertId, string ExpectedState, string State);
public sealed record AlertStateChangeResponse(int SchemaVersion, Guid RequestId, bool Accepted, string ResultCode);

public static class SecurityEventCatalog
{
    private static readonly IReadOnlyDictionary<(string Log, int Id), SecurityEventRule> Rules =
        new Dictionary<(string Log, int Id), SecurityEventRule>(new LogEventKeyComparer())
        {
            [("System", 7045)] = new("HIGH", "T1543.003", "Windows service installed"),
            [("System", 104)] = new("CRITICAL", "T1070.001", "System event log cleared"),
            [("Security", 4698)] = new("HIGH", "T1053.005", "Scheduled task created"),
            [("Security", 4699)] = new("LOW", "T1053.005", "Scheduled task deleted"),
            [("Security", 4720)] = new("MEDIUM", "T1136.001", "User account created"),
            [("Security", 4726)] = new("MEDIUM", "T1531", "User account deleted"),
            [("Security", 4732)] = new("MEDIUM", "T1078", "Member added to local security group"),
            [("Security", 4728)] = new("MEDIUM", "T1078", "Member added to global security group"),
            [("Security", 4740)] = new("MEDIUM", "T1078.001", "User account locked out"),
            [("Security", 4776)] = new("LOW", "T1110.003", "NTLM credential validation failed"),
            [("Security", 1102)] = new("CRITICAL", "T1070.001", "Security audit log cleared"),
            [("Security", 4625)] = new("HIGH", "T1110", "Brute-force logon burst detected"),
            [("Security", 4672)] = new("LOW", "T1134", "Special privileges assigned to new logon"),
            [("Security", 4673)] = new("LOW", "T1134", "Sensitive privilege use recorded"),
            [("Security", 4688)] = new("LOW", "T1059", "Process creation recorded"),
            [("Security", 4663)] = new("LOW", "T1078", "Object access attempted"),
            [("Security", 4697)] = new("HIGH", "T1543.003", "Service installed (security audit)"),
            [("Security", 4738)] = new("LOW", "T1136", "User account changed"),
            [("Microsoft-Windows-PowerShell/Operational", 4104)] = new("LOW", "T1059.001", "PowerShell script block recorded"),
            [("Microsoft-Windows-Windows Defender/Operational", 5001)] = new("CRITICAL", "T1562.001", "Defender real-time protection disabled"),
            [("Microsoft-Windows-Windows Defender/Operational", 5007)] = new("HIGH", "T1562.001", "Defender configuration changed"),
            [("Microsoft-Windows-Windows Defender/Operational", 5010)] = new("HIGH", "T1562.001", "Defender service not running"),
            [("Microsoft-Windows-Windows Defender/Operational", 5012)] = new("HIGH", "T1562.001", "Defender antivirus engine update failed"),
            [("Microsoft-Windows-Windows Defender/Operational", 1116)] = new("HIGH", "T1204", "Defender detected malware"),
            [("Microsoft-Windows-Windows Defender/Operational", 1117)] = new("HIGH", "T1204", "Defender took a malware remediation action"),
            [("Microsoft-Windows-Windows Defender/Operational", 5004)] = new("MEDIUM", "T1562.001", "Defender scan stopped"),
            [("Microsoft-Windows-Windows Defender/Operational", 5003)] = new("MEDIUM", "T1562.001", "Defender protection or scan configuration changed"),
            [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21)] = new("MEDIUM", "T1021.001", "Remote Desktop session logon"),
            [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 22)] = new("LOW", "T1021.001", "Remote Desktop shell started"),
            [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 24)] = new("LOW", "T1021.001", "Remote Desktop session disconnected"),
            [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 25)] = new("LOW", "T1021.001", "Remote Desktop session reconnected"),
            [("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149)] = new("HIGH", "T1021.001", "Remote Desktop connection authenticated"),
            [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 5156)] = new("LOW", "T1071", "Firewall permitted a connection"),
            [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 5157)] = new("MEDIUM", "T1071", "Firewall blocked a connection"),
            [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 5152)] = new("MEDIUM", "T1071", "Firewall dropped a packet")
        };

    public static IReadOnlyCollection<int> WatchedEventIds => Rules.Keys.Select(key => key.Id).Distinct().Order().ToArray();

    public static IReadOnlyCollection<(string LogName, int EventId)> WatchedEvents =>
        Rules.Keys.OrderBy(key => key.Log, StringComparer.OrdinalIgnoreCase).ThenBy(key => key.Id).ToArray();

    public static bool TryGetRule(string logName, int eventId, out SecurityEventRule rule) =>
        Rules.TryGetValue((logName, eventId), out rule!);

    private sealed class LogEventKeyComparer : IEqualityComparer<(string Log, int Id)>
    {
        public bool Equals((string Log, int Id) x, (string Log, int Id) y) =>
            x.Id == y.Id && StringComparer.OrdinalIgnoreCase.Equals(x.Log, y.Log);

        public int GetHashCode((string Log, int Id) value) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(value.Log), value.Id);
    }
}

public sealed record SecurityEventRule(string Severity, string Technique, string Summary);

public sealed record SysmonObservation(
    string LogName,
    string Provider,
    int EventId,
    long? RecordId,
    DateTimeOffset? CreatedAtUtc,
    string Severity,
    string Technique,
    string Summary,
    int Occurrences = 1);

public sealed record SysmonSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<SysmonObservation> Events,
    int SourcesQueried,
    IReadOnlyList<string> Warnings);

public static class SysmonCatalog
{
    private static readonly IReadOnlyDictionary<(string Log, int Id), SysmonRule> Rules =
        new Dictionary<(string Log, int Id), SysmonRule>(new LogEventKeyComparer())
        {
            [("Microsoft-Windows-Sysmon/Operational", 1)] = new("CRITICAL", "T1543.003", "Process creation"),
            [("Microsoft-Windows-Sysmon/Operational", 2)] = new("HIGH", "T1543.003", "File creation time modification"),
            [("Microsoft-Windows-Sysmon/Operational", 3)] = new("HIGH", "T1070.004", "Network connection"),
            [("Microsoft-Windows-Sysmon/Operational", 4)] = new("MEDIUM", "T1105", "File creation"),
            [("Microsoft-Windows-Sysmon/Operational", 5)] = new("MEDIUM", "T1070.004", "Process termination"),
            [("Microsoft-Windows-Sysmon/Operational", 6)] = new("MEDIUM", "T1105", "Driver load"),
            [("Microsoft-Windows-Sysmon/Operational", 7)] = new("HIGH", "T1105", "Image load"),
            [("Microsoft-Windows-Sysmon/Operational", 8)] = new("HIGH", "T1055", "CreateRemoteThread"),
            [("Microsoft-Windows-Sysmon/Operational", 9)] = new("CRITICAL", "T1106", "RawAccessRead"),
            [("Microsoft-Windows-Sysmon/Operational", 10)] = new("HIGH", "T1106", "Process access"),
            [("Microsoft-Windows-Sysmon/Operational", 11)] = new("HIGH", "T1106", "File creation"),
            [("Microsoft-Windows-Sysmon/Operational", 12)] = new("HIGH", "T1070.004", "File creation time modification"),
            [("Microsoft-Windows-Sysmon/Operational", 13)] = new("HIGH", "T1106", "Registry creation/deletion"),
            [("Microsoft-Windows-Sysmon/Operational", 14)] = new("HIGH", "T1106", "Registry value modification"),
            [("Microsoft-Windows-Sysmon/Operational", 15)] = new("HIGH", "T1106", "File stream creation"),
            [("Microsoft-Windows-Sysmon/Operational", 16)] = new("HIGH", "T1106", "Named pipe creation"),
            [("Microsoft-Windows-Sysmon/Operational", 17)] = new("HIGH", "T1106", "WMI event filter"),
            [("Microsoft-Windows-Sysmon/Operational", 18)] = new("HIGH", "T1106", "WMI event consumer"),
            [("Microsoft-Windows-Sysmon/Operational", 19)] = new("HIGH", "T1106", "WMI filter to consumer binding"),
            [("Microsoft-Windows-Sysmon/Operational", 20)] = new("HIGH", "T1106", "WMI event filter"),
            [("Microsoft-Windows-Sysmon/Operational", 21)] = new("MEDIUM", "T1106", "File deletion"),
            [("Microsoft-Windows-Sysmon/Operational", 22)] = new("HIGH", "T1106", "File deletion"),
            [("Microsoft-Windows-Sysmon/Operational", 23)] = new("HIGH", "T1106", "File deletion"),
            [("Microsoft-Windows-Sysmon/Operational", 24)] = new("HIGH", "T1106", "File deletion"),
            [("Microsoft-Windows-Sysmon/Operational", 25)] = new("MEDIUM", "T1106", "File deletion"),
            [("Microsoft-Windows-Sysmon/Operational", 26)] = new("MEDIUM", "T1106", "File deletion"),
            [("Microsoft-Windows-Sysmon/Operational", 255)] = new("HIGH", "T1027", "Sysmon configuration state change"),
            [("Microsoft-Windows-Sysmon/Operational", 256)] = new("HIGH", "T1027", "Sysmon configuration state change"),
            [("Microsoft-Windows-Sysmon/Operational", 257)] = new("HIGH", "T1027", "Sysmon configuration state change"),
            [("Microsoft-Windows-Sysmon/Operational", 258)] = new("HIGH", "T1027", "Sysmon configuration state change"),
        };

    public static IReadOnlyCollection<int> WatchedEventIds => Rules.Keys.Select(key => key.Id).Distinct().Order().ToArray();

    public static IReadOnlyCollection<(string LogName, int EventId)> WatchedEvents =>
        Rules.Keys.OrderBy(key => key.Log, StringComparer.OrdinalIgnoreCase).ThenBy(key => key.Id).ToArray();

    public static bool TryGetRule(string logName, int eventId, out SysmonRule rule) =>
        Rules.TryGetValue((logName, eventId), out rule!);

    private sealed class LogEventKeyComparer : IEqualityComparer<(string Log, int Id)>
    {
        public bool Equals((string Log, int Id) x, (string Log, int Id) y) =>
            x.Id == y.Id && StringComparer.OrdinalIgnoreCase.Equals(x.Log, y.Log);

        public int GetHashCode((string Log, int Id) value) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(value.Log), value.Id);
    }
}

public sealed record SysmonRule(string Severity, string Technique, string Summary);
