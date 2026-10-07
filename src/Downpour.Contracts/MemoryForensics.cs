namespace Downpour.Contracts;

public sealed record ProcessMemoryInspection(
    int ProcessId,
    string ProcessName,
    string ExecutablePath,
    long WorkingSetBytes,
    int ThreadCount,
    int InjectionScore,
    string Classification,
    string Severity,
    IReadOnlyList<string> Findings,
    string SuspectedTechnique);

public sealed record MemoryForensicsSummary(
    int TotalProcessesScanned,
    int InjectedCount,
    int SuspiciousCount,
    int CleanCount,
    IReadOnlyList<ProcessMemoryInspection> HighRiskProcesses,
    IReadOnlyList<ProcessMemoryInspection> AllInspections,
    DateTimeOffset InspectedAtUtc,
    string SecurityNotice);
