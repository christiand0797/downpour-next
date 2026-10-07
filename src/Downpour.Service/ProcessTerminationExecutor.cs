using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

public sealed record ProcessTerminationOutcome(
    bool Succeeded,
    string ResultCode,
    string Message,
    int ProcessId,
    string? ProcessName = null);

public sealed record ProcessCandidate(
    int ProcessId,
    string ProcessName,
    string ImagePath,
    DateTimeOffset StartTimeUtc,
    string? DenyReason);

public sealed class ProcessTerminationRejectedException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>
/// Executes audited, policy-checked process termination (DN-008 Phase 2).
/// Enforces an immutable deny-list of system and Downpour processes, binds PID to process creation time
/// to prevent recycled PID race conditions, and records all actions to the audit log.
/// </summary>
public sealed class ProcessTerminationExecutor
{
    private static readonly HashSet<string> CriticalSystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss",
        "lsass",
        "services",
        "wininit",
        "winlogon",
        "smss",
        "svchost",
        "dwm",
        "fontdrvhost",
        "explorer"
    };

    private static readonly HashSet<string> DownpourProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "downpour.desktop",
        "downpour.service",
        "downpour.scanner",
        "downpour.updatehelper"
    };

    private static readonly HashSet<string> SecurityProductProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng", "NisSrv", "MpDefenderCoreService", "MsSense", "SenseCncProxy", "SecurityHealthService",
        "SecurityHealthSystray", "SgrmBroker", "MBAMService", "mbamtray", "ekrn", "avp", "bdservicehost", "ccSvcHst",
        "mcshield", "AvastSvc", "AVGSvc", "SophosHealth", "CSFalconService", "SentinelAgent", "WRSA",
    };

    private static bool IsUnderWindowsDirectory(string imagePath) =>
        IsUnder(imagePath, Environment.GetFolderPath(Environment.SpecialFolder.Windows));

    private static bool IsUnderProtectedInstallRoot(string imagePath) =>
        IsUnderWindowsDirectory(imagePath)
        || IsUnder(imagePath, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))
        || IsUnder(imagePath, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86))
        || IsUnder(imagePath, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender"));

    private static bool IsUnder(string path, string root) =>
        !string.IsNullOrEmpty(root) && path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

    private readonly int? _parentProcessId;

    public ProcessTerminationExecutor(int? parentProcessId = null)
    {
        _parentProcessId = parentProcessId;
    }

    /// <summary>
    /// Checks whether a process is in the immutable deny-list.
    /// Returns null if termination is allowed, or a human-readable denial reason.
    /// </summary>
    public string? DenyReason(int pid, string? processName, string? imagePath)
    {
        if (pid <= 4)
            return $"Process ID {pid} is an essential Windows kernel or idle system process and cannot be terminated.";

        if (pid == Environment.ProcessId)
            return "The Downpour service cannot terminate its own process.";

        if (_parentProcessId.HasValue && pid == _parentProcessId.Value)
            return "The Downpour service cannot terminate the Downpour desktop interface.";

        var name = !string.IsNullOrWhiteSpace(processName)
            ? Path.GetFileNameWithoutExtension(processName)
            : (!string.IsNullOrWhiteSpace(imagePath) ? Path.GetFileNameWithoutExtension(imagePath) : null);

        if (name is not null)
        {
            // Critical names are protected only where Windows installs them (or when the image path is unknown, failing
            // closed). Malware commonly runs as "svchost.exe" or "explorer.exe" from user folders; that copy may be ended.
            if (CriticalSystemProcessNames.Contains(name) && (string.IsNullOrWhiteSpace(imagePath) || IsUnderWindowsDirectory(imagePath)))
                return $"Process '{name}' is an essential Windows operating system component and cannot be terminated.";

            if (SecurityProductProcessNames.Contains(name) && (string.IsNullOrWhiteSpace(imagePath) || IsUnderProtectedInstallRoot(imagePath)))
                return $"Process '{name}' belongs to installed security software and cannot be terminated.";

            if (DownpourProcessNames.Contains(name))
                return $"Process '{name}' is a core Downpour application component and cannot be terminated.";
        }

        if (!string.IsNullOrWhiteSpace(imagePath))
        {
            var lower = imagePath.ToLowerInvariant();
            if (lower.Contains(@"\windows\system32\csrss.exe") ||
                lower.Contains(@"\windows\system32\lsass.exe") ||
                lower.Contains(@"\windows\system32\services.exe") ||
                lower.Contains(@"\windows\system32\wininit.exe") ||
                lower.Contains(@"\windows\system32\winlogon.exe") ||
                lower.Contains(@"\windows\system32\smss.exe"))
            {
                return "Target image is a protected Windows system critical binary and cannot be terminated.";
            }
        }

        return null;
    }

    /// <summary>
    /// Inspects a running process to verify existence, start time binding, and deny-list status.
    /// </summary>
    public ProcessCandidate Inspect(int pid, DateTimeOffset expectedStartTimeUtc)
    {
        if (DenyReason(pid, null, null) is { } pidDeny)
        {
            return new ProcessCandidate(pid, $"PID-{pid}", "", expectedStartTimeUtc, pidDeny);
        }

        using var handle = OpenProcess(ProcessQueryLimitedInformation | Synchronize, false, (uint)pid);
        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == 5) // ERROR_ACCESS_DENIED
                throw new ProcessTerminationRejectedException("access-denied", $"Access is denied for process {pid}. It may be a protected system process (PPL) or require higher privileges.");
            if (err is 87 or 1168) // ERROR_INVALID_PARAMETER or ERROR_NOT_FOUND
                throw new ProcessTerminationRejectedException("process-not-found", $"Process with PID {pid} is not running.");

            throw new ProcessTerminationRejectedException("process-inspect-failed", $"Failed to inspect process {pid} (Win32 error {err}).");
        }

        if (GetExitCodeProcess(handle, out var exitCode) && exitCode != 259) // 259 = STILL_ACTIVE
        {
            throw new ProcessTerminationRejectedException("process-already-exited", $"Process with PID {pid} has already exited with code {exitCode}.");
        }

        var buffer = new char[1024];
        uint size = (uint)buffer.Length;
        string imagePath = "";
        string processName = "";
        if (QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0)
        {
            imagePath = new string(buffer, 0, (int)size);
            processName = Path.GetFileName(imagePath);
        }
        else
        {
            processName = $"PID-{pid}";
        }

        var deny = DenyReason(pid, processName, imagePath);

        if (!GetProcessTimes(handle, out var creationTime, out _, out _, out _))
        {
            throw new ProcessTerminationRejectedException("process-inspect-failed", "Failed to retrieve process creation time.");
        }

        var actualStart = DateTimeOffset.FromFileTime(creationTime).ToUniversalTime();
        if (expectedStartTimeUtc != DateTimeOffset.MinValue)
        {
            var diff = Math.Abs((actualStart - expectedStartTimeUtc).TotalSeconds);
            if (diff > 3.0)
            {
                throw new ProcessTerminationRejectedException("process-identity-mismatched",
                    $"Process start time mismatch: process started at {actualStart:u}, expected {expectedStartTimeUtc:u}. The PID may have been recycled.");
            }
        }

        return new ProcessCandidate(pid, processName, imagePath, actualStart, deny);
    }

    /// <summary>
    /// Executes process termination on a validated candidate.
    /// </summary>
    public async Task<ProcessTerminationOutcome> TerminateAsync(
        int pid,
        DateTimeOffset expectedStartTimeUtc,
        string reason,
        CancellationToken cancellationToken)
    {
        await Task.Yield();

        ProcessCandidate candidate;
        try
        {
            candidate = Inspect(pid, expectedStartTimeUtc);
        }
        catch (ProcessTerminationRejectedException ex)
        {
            return new ProcessTerminationOutcome(false, ex.Code, ex.Message, pid);
        }

        if (candidate.DenyReason is not null)
        {
            return new ProcessTerminationOutcome(false, "denied-protected-process", candidate.DenyReason, pid, candidate.ProcessName);
        }

        using var handle = OpenProcess(ProcessTerminate | ProcessQueryLimitedInformation | Synchronize, false, (uint)pid);
        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == 5)
                return new ProcessTerminationOutcome(false, "access-denied", $"Access denied terminating process {pid}.", pid, candidate.ProcessName);

            return new ProcessTerminationOutcome(false, "process-open-failed", $"Failed to open process {pid} for termination (Win32 error {err}).", pid, candidate.ProcessName);
        }

        if (GetProcessTimes(handle, out var creationTime, out _, out _, out _))
        {
            var actualStart = DateTimeOffset.FromFileTime(creationTime).ToUniversalTime();
            if (Math.Abs((actualStart - candidate.StartTimeUtc).TotalSeconds) > 3.0)
            {
                return new ProcessTerminationOutcome(false, "process-identity-mismatched", "Process start time changed between inspection and termination.", pid, candidate.ProcessName);
            }
        }

        if (!TerminateProcess(handle, 1))
        {
            int err = Marshal.GetLastWin32Error();
            return new ProcessTerminationOutcome(false, "termination-failed", $"Failed to terminate process {pid} (Win32 error {err}).", pid, candidate.ProcessName);
        }

        WaitForSingleObject(handle, 2000);

        return new ProcessTerminationOutcome(
            true,
            "terminated",
            $"Process '{candidate.ProcessName}' (PID {pid}) terminated successfully.",
            pid,
            candidate.ProcessName);
    }

    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle hProcess,
        out long lpCreationTime,
        out long lpExitTime,
        out long lpKernelTime,
        out long lpUserTime);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(
        SafeProcessHandle hProcess,
        uint flags,
        [Out] char[] lpExeName,
        ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle hHandle, uint dwMilliseconds);
}
