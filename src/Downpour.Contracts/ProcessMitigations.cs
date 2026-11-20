namespace Downpour.Contracts;

/// <summary>
/// One image's read-only exploit-mitigation reading. Every value is the policy Windows reports for the running
/// process, the same source as the Exploit protection page; Downpour never changes a policy. A process that will not
/// answer the query is counted in <see cref="ProcessMitigationSnapshot.RefusedCount"/>, never reported as exposed.
/// </summary>
public sealed record ProcessMitigationEntry(
    string ProcessName,
    int ProcessId,
    int InstanceCount,
    bool ControlFlowGuard,
    bool ArbitraryCodeGuard,
    bool CodeIntegrityGuard,
    bool BlocksNonMicrosoftDlls,
    bool Dep,
    bool Aslr);

/// <summary>
/// Per-image exploit mitigations, which machine-wide hardening checks cannot express: a browser without CFG/ACG or a
/// mail client that still loads non-Microsoft DLLs is exposed in a way the hardening page never showed.
/// <see cref="RefusedCount"/> keeps a short list from looking like full coverage.
/// </summary>
public sealed record ProcessMitigationSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<ProcessMitigationEntry> Processes,
    int RefusedCount,
    IReadOnlyList<string> Warnings);

public static class ProcessMitigationLimits
{
    public const int MaximumProcesses = 64;
    public const int MaximumWarnings = 8;
    public const int MaximumNameLength = 128;
    public const int MaximumInstances = 10_000;
    public const int MaximumRefused = 100_000;
}
