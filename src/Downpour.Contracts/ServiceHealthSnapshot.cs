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
