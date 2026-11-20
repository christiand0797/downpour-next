using System.Diagnostics;
using System.Runtime.InteropServices;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Reads the exploit-mitigation policy Windows applies to running images. This is the same per-image policy the
/// Exploit protection settings page edits; it is not a signature check and not a malware verdict. Read-only: each
/// process is opened for query access only, and a process that refuses is counted rather than called exposed.
/// </summary>
public sealed class ProcessMitigationProvider
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessQueryInformation = 0x0400;
    private const int MaximumScanned = 2048;

    // PROCESS_MITIGATION_POLICY values from winnt.h.
    private const int PolicyDep = 0;
    private const int PolicyAslr = 1;
    private const int PolicyDynamicCode = 2;
    private const int PolicyControlFlowGuard = 7;
    private const int PolicySignature = 8;

    public ProcessMitigationSnapshot Capture()
    {
        try
        {
            return CaptureCore();
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            return new ProcessMitigationSnapshot(1, DateTimeOffset.UtcNow, [], 0,
                ["This Windows version does not expose per-process mitigation policies."]);
        }
    }

    private static ProcessMitigationSnapshot CaptureCore()
    {
        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new ProcessMitigationSnapshot(1, DateTimeOffset.UtcNow, [], 0,
                [$"The process list could not be read ({ex.GetType().Name})."]);
        }

        var readable = new List<ProcessMitigationEntry>(64);
        var refused = 0;
        var scanned = 0;
        foreach (var process in processes)
        {
            if (scanned++ >= MaximumScanned) break;
            using (process)
            {
                // Idle and System are kernel pseudo-processes; querying them would only inflate the refusal count.
                if (process.Id <= 4) continue;
                string name;
                try
                {
                    name = process.ProcessName;
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    refused++;
                    continue;
                }
                if (string.IsNullOrWhiteSpace(name))
                {
                    refused++;
                    continue;
                }
                if (name.Length > ProcessMitigationLimits.MaximumNameLength)
                    name = name[..ProcessMitigationLimits.MaximumNameLength];
                if (Read(process.Id, name) is { } entry) readable.Add(entry);
                else refused++;
            }
        }

        var selected = SelectRepresentatives(readable);
        IReadOnlyList<string> warnings = selected.Count == 0
            ? ["No process answered the mitigation query for this account."]
            : [];
        return new ProcessMitigationSnapshot(1, DateTimeOffset.UtcNow, selected, refused, warnings);
    }

    private static ProcessMitigationEntry? Read(int processId, string name)
    {
        // The DEP policy rejects a PROCESS_QUERY_LIMITED_INFORMATION handle with ERROR_ACCESS_DENIED while the other
        // policies accept it, so a complete reading needs full query rights. A process that grants only the limited
        // handle is counted as refused rather than reported with a guessed DEP value.
        var handle = OpenProcess(ProcessQueryInformation | ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero) return null;
        try
        {
            if (!QueryDep(handle, out var dep)
                || !Query(handle, PolicyAslr, out var aslr)
                || !Query(handle, PolicyDynamicCode, out var dynamicCode)
                || !Query(handle, PolicyControlFlowGuard, out var cfg)
                || !Query(handle, PolicySignature, out var signature))
                return null;
            return Decode(name, processId, dep, aslr, dynamicCode, cfg, signature);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// Decodes the raw policy bitfields. Public for the regression tests: reading the wrong bit would silently label
    /// an exposed image as protected.
    /// </summary>
    public static ProcessMitigationEntry Decode(string name, int processId, uint dep, uint aslr, uint dynamicCode, uint cfg, uint signature) =>
        new(name, processId, 1,
            ControlFlowGuard: (cfg & 0x1) != 0,
            ArbitraryCodeGuard: (dynamicCode & 0x1) != 0,
            CodeIntegrityGuard: (signature & 0x3) != 0,
            BlocksNonMicrosoftDlls: (signature & 0x20) != 0,
            Dep: (dep & 0x1) != 0,
            Aslr: (aslr & 0x3) != 0);

    /// <summary>
    /// One row per image name: browsers and editors run many identical processes, so the worst instance represents the
    /// name and InstanceCount says how many were folded in. High-value images come first, then the lowest score.
    /// </summary>
    public static IReadOnlyList<ProcessMitigationEntry> SelectRepresentatives(IReadOnlyList<ProcessMitigationEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var representatives = new List<ProcessMitigationEntry>();
        foreach (var group in entries.GroupBy(entry => entry.ProcessName, StringComparer.OrdinalIgnoreCase))
        {
            var worst = group.OrderBy(Score).ThenBy(entry => entry.ProcessId).First();
            representatives.Add(worst with { InstanceCount = group.Count() });
        }
        return representatives
            .OrderByDescending(entry => ExploitMitigationPosture.HighValueProcesses.Contains(entry.ProcessName))
            .ThenBy(Score)
            .ThenBy(entry => entry.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Take(ProcessMitigationLimits.MaximumProcesses)
            .ToArray();
    }

    private static int Score(ProcessMitigationEntry entry) => ExploitMitigationPosture.Assess(ExploitMitigationPosture.FromEntry(entry)).Score;

    private static bool Query(IntPtr handle, int policy, out uint flags)
    {
        flags = 0;
        var buffer = new FlagsPolicy();
        if (!GetProcessMitigationPolicy(handle, policy, ref buffer, (nuint)Marshal.SizeOf<FlagsPolicy>())) return false;
        flags = buffer.Flags;
        return true;
    }

    private static bool QueryDep(IntPtr handle, out uint flags)
    {
        flags = 0;
        var buffer = new DepPolicy();
        if (!GetProcessMitigationPolicy(handle, PolicyDep, ref buffer, (nuint)Marshal.SizeOf<DepPolicy>())) return false;
        flags = buffer.Flags;
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FlagsPolicy
    {
        public uint Flags;
    }

    /// <summary>PROCESS_MITIGATION_DEP_POLICY is a DWORD plus a BOOLEAN, padded to eight bytes.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct DepPolicy
    {
        public uint Flags;
        public byte Permanent;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetProcessMitigationPolicy", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMitigationPolicy(IntPtr process, int policy, ref FlagsPolicy buffer, nuint size);

    [DllImport("kernel32.dll", EntryPoint = "GetProcessMitigationPolicy", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMitigationPolicy(IntPtr process, int policy, ref DepPolicy buffer, nuint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
