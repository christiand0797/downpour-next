using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>A process ID that answered a direct probe (OpenProcess), with what was learned about it.</summary>
public sealed record ProbedProcess(int ProcessId, bool Running, string? ImagePath, DateTimeOffset? StartedUtc);

/// <summary>A running process that Windows' process list did not show.</summary>
public sealed record HiddenProcess(int ProcessId, string? ImagePath, DateTimeOffset? StartedUtc);

/// <summary>
/// Cross-view rootkit check (v29 RootkitDetector, rebuilt): every process ID is probed directly and compared with the
/// system process list taken before and after the probe. A process that is running, answers a probe, and is missing
/// from both lists is being hidden from the list (a user- or kernel-mode rootkit technique, MITRE T1014). Exited
/// "zombie" processes (still referenced by a handle), processes started during the scan, and PIDs that appear in either
/// list are never reported, so ordinary process churn cannot raise a false alarm.
/// </summary>
public static class HiddenProcessAnalyzer
{
    public const int MaximumReported = 32;

    public static IReadOnlyList<HiddenProcess> Find(
        IReadOnlySet<int> listedBefore, IReadOnlySet<int> listedAfter, IEnumerable<ProbedProcess> probed, DateTimeOffset scanStartedUtc)
    {
        var hidden = new List<HiddenProcess>();
        foreach (var p in probed)
        {
            if (p.ProcessId <= 4 || !p.Running) continue;
            if (listedBefore.Contains(p.ProcessId) || listedAfter.Contains(p.ProcessId)) continue;
            if (p.StartedUtc is null || p.StartedUtc >= scanStartedUtc.AddSeconds(-2)) continue; // started during the scan, or unknown
            hidden.Add(new HiddenProcess(p.ProcessId, p.ImagePath, p.StartedUtc));
            if (hidden.Count >= MaximumReported) break;
        }
        return hidden;
    }

    public static IReadOnlyList<SecurityFindingObservation> ToFindings(IReadOnlyList<HiddenProcess> hidden) =>
        hidden.Select(h => SecurityFindingMapper.Create(SecurityFindingCatalog.Rootkit, "Hidden process", "CRITICAL", "T1014",
                $"Process hidden from Windows' process list: {(h.ImagePath is { } path ? Path.GetFileName(path) : "unknown program")} (PID {h.ProcessId})",
                h.ImagePath ?? $"pid:{h.ProcessId}"))
            .ToArray();
}
