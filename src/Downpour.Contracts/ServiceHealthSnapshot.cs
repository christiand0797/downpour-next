namespace Downpour.Contracts;

public sealed record ServiceHealthSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string ServiceState,
    string OperatingMode,
    IReadOnlyList<string> ConnectedSensors,
    IReadOnlyList<string> Warnings);

public sealed record ProcessSnapshot(int ProcessId, string Name, long WorkingSetBytes, int ThreadCount);

public sealed record SystemHealthSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    int ProcessCount,
    double? CpuPercent,
    ulong MemoryTotalBytes,
    ulong MemoryAvailableBytes,
    int? ActiveTcpConnections,
    IReadOnlyList<ProcessSnapshot> TopProcesses,
    IReadOnlyList<string> Warnings);

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
    string StartupType);

public sealed record WindowsServiceInventorySnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string CollectionStatus,
    int ServiceCount,
    IReadOnlyList<WindowsServiceInventoryEntry> Services,
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
    string State);

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
