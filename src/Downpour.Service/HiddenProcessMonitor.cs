using System.Diagnostics;
using System.Runtime.InteropServices;
using Downpour.Core;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

/// <summary>
/// Runs the cross-view hidden-process check (see <see cref="HiddenProcessAnalyzer"/>) a minute after start and every
/// ten minutes: lists processes, probes every process ID with PROCESS_QUERY_LIMITED_INFORMATION, lists again, and
/// re-probes any suspect. Read-only; a probe opens and immediately closes a query-only handle.
/// </summary>
public sealed class HiddenProcessMonitor(SecurityAlertRepository alerts, ILogger<HiddenProcessMonitor> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(10);
    private const int HighestProbedPid = 1 << 20;
    private const uint QueryLimited = 0x1000;
    private const int StillActive = 259;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); }
        catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var hidden = await Task.Run(() => Scan(stoppingToken), stoppingToken);
                if (hidden.Count > 0)
                {
                    logger.LogWarning("{Count} process(es) answered direct probes but are missing from the process list.", hidden.Count);
                    await alerts.IngestFindingsAsync(HiddenProcessAnalyzer.ToFindings(hidden), DateTimeOffset.UtcNow, stoppingToken);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "The hidden-process check failed.");
            }
            try { await Task.Delay(Interval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal static IReadOnlyList<HiddenProcess> Scan(CancellationToken token)
    {
        var started = DateTimeOffset.UtcNow;
        var before = ListedPids();
        var suspects = new List<int>();
        for (var pid = 8; pid < HighestProbedPid; pid += 4)
        {
            if ((pid & 0xFFFF) == 0) token.ThrowIfCancellationRequested();
            if (before.Contains(pid)) continue;
            using var handle = OpenProcess(QueryLimited, false, (uint)pid);
            if (!handle.IsInvalid) suspects.Add(pid);
        }
        if (suspects.Count == 0) return [];

        var after = ListedPids();
        var probed = suspects.Where(pid => !after.Contains(pid)).Select(Probe).ToArray();
        // A second list after probing closes the last race with processes that just started.
        var final = ListedPids();
        return HiddenProcessAnalyzer.Find(before, new HashSet<int>(after.Concat(final)), probed, started);
    }

    private static HashSet<int> ListedPids()
    {
        var pids = new HashSet<int>();
        foreach (var process in Process.GetProcesses())
        {
            using (process) pids.Add(process.Id);
        }
        return pids;
    }

    private static ProbedProcess Probe(int pid)
    {
        using var handle = OpenProcess(QueryLimited, false, (uint)pid);
        if (handle.IsInvalid) return new ProbedProcess(pid, false, null, null);
        // A zombie (exited, still referenced by a handle) is not running; a reused ID must still be this PID.
        var running = GetExitCodeProcess(handle, out var code) && code == StillActive && GetProcessId(handle) == pid;
        string? path = null;
        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        if (QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0) path = new string(buffer, 0, (int)size);
        DateTimeOffset? startedUtc = GetProcessTimes(handle, out var creation, out _, out _, out _) && creation > 0
            ? DateTimeOffset.FromFileTime(creation).ToUniversalTime() : null;
        return new ProbedProcess(pid, running, path, startedUtc);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int GetProcessId(SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);
}
