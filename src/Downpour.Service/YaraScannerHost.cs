using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Downpour.Contracts;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

public interface IYaraScannerBackend : IDisposable
{
    ScannerReady? Ready { get; }
    Task<ScannerReady> EnsureStartedAsync(CancellationToken token);
    Task<ScannerFileResult> ScanAsync(string path, CancellationToken token);
}

/// <summary>
/// Runs Downpour.Scanner.exe (bundled next to the service, no arguments) inside a job object that kills it when the
/// service exits, caps its memory at 1.5 GiB, and forbids child processes. A crash or hang only fails the current file;
/// the helper is restarted on the next request.
/// </summary>
public sealed class YaraScannerHost(ILogger<YaraScannerHost> logger, string? scannerPath = null) : IYaraScannerBackend
{
    public static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(90);
    public static readonly TimeSpan FileTimeout = TimeSpan.FromSeconds(30);
    private const int MaximumLineChars = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private SafeFileHandle? _job;
    private long _nextId;

    public ScannerReady? Ready { get; private set; }

    public static string DefaultPath()
    {
        var baseDirectory = AppContext.BaseDirectory;
        return Path.Combine(baseDirectory, "scanner", "Downpour.Scanner.exe");
    }

    public async Task<ScannerReady> EnsureStartedAsync(CancellationToken token)
    {
        await _gate.WaitAsync(token);
        try { return await EnsureStartedLockedAsync(token); }
        finally { _gate.Release(); }
    }

    public async Task<ScannerFileResult> ScanAsync(string path, CancellationToken token)
    {
        await _gate.WaitAsync(token);
        try
        {
            var ready = await EnsureStartedLockedAsync(token);
            if (ready.Fatal is not null || _process is null) return new(-1, "error", "The scanner is unavailable: " + (ready.Fatal ?? "not running"), 0, []);
            var id = ++_nextId;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(FileTimeout);
            try
            {
                await _process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new ScannerFileRequest(id, path), Json).AsMemory(), timeout.Token);
                await _process.StandardInput.FlushAsync(timeout.Token);
                var line = await ReadLineAsync(_process.StandardOutput, timeout.Token);
                var result = line is null ? null : JsonSerializer.Deserialize<ScannerFileResult>(line, Json);
                if (result is null || result.Id != id) throw new InvalidDataException("The scanner returned an invalid reply.");
                return result;
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidDataException or JsonException or InvalidOperationException)
            {
                if (token.IsCancellationRequested) throw new OperationCanceledException(token);
                logger.LogWarning("The YARA scanner stopped responding on a file and was restarted ({Type}).", ex.GetType().Name);
                StopLocked();
                return new(id, "error", "The scanner stopped responding on this file and was restarted.", 0, []);
            }
        }
        finally { _gate.Release(); }
    }

    private async Task<ScannerReady> EnsureStartedLockedAsync(CancellationToken token)
    {
        if (_process is { HasExited: false } && Ready is not null) return Ready;
        StopLocked();
        var path = scannerPath ?? DefaultPath();
        if (!File.Exists(path)) return Ready = new ScannerReady(1, "", 0, [], "The scanner helper is not installed with this build.");
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo(path)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = false,
                    WorkingDirectory = Path.GetDirectoryName(path)!,
                    StandardInputEncoding = new UTF8Encoding(false),
                    StandardOutputEncoding = new UTF8Encoding(false),
                },
            };
            process.Start();
            _process = process;
            _job = CreateLimitedJob();
            if (_job is null || !AssignProcessToJobObject(_job, process.SafeHandle))
            {
                StopLocked();
                return Ready = new ScannerReady(1, "", 0, [], "The scanner could not be placed in its resource-limited job.");
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(StartTimeout);
            var line = await ReadLineAsync(process.StandardOutput, timeout.Token);
            var ready = line is null ? null : JsonSerializer.Deserialize<ScannerReady>(line, Json);
            if (ready is not { SchemaVersion: 1 }) throw new InvalidDataException("The scanner did not report ready.");
            if (ready.Fatal is not null) StopLocked();
            Ready = ready;
            logger.LogInformation("YARA scanner ready: YARA-X {Version}, {Rules} rules, {Failed} rule file(s) not loaded.",
                ready.EngineVersion, ready.RuleCount, ready.RuleFiles.Count(file => !file.Loaded));
            return ready;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidDataException or JsonException or InvalidOperationException or OperationCanceledException)
        {
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
            StopLocked();
            logger.LogWarning(ex, "The YARA scanner helper could not start.");
            return Ready = new ScannerReady(1, "", 0, [], "The scanner helper could not start.");
        }
    }

    private static async Task<string?> ReadLineAsync(StreamReader reader, CancellationToken token)
    {
        var line = await reader.ReadLineAsync(token);
        return line is { Length: > MaximumLineChars } ? throw new InvalidDataException("The scanner reply was too large.") : line;
    }

    private void StopLocked()
    {
        if (_process is not null)
        {
            try { if (!_process.HasExited) _process.Kill(entireProcessTree: true); }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception) { }
            _process.Dispose();
            _process = null;
        }
        _job?.Dispose();
        _job = null;
    }

    public void Dispose()
    {
        _gate.Wait();
        try { StopLocked(); }
        finally { _gate.Release(); }
    }

    private static SafeFileHandle? CreateLimitedJob()
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) return null;
        var info = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                // KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION | ACTIVE_PROCESS | PROCESS_MEMORY
                LimitFlags = 0x2000 | 0x400 | 0x8 | 0x100,
                ActiveProcessLimit = 1,
            },
            ProcessMemoryLimit = (UIntPtr)(1536UL * 1024 * 1024),
        };
        if (!SetInformationJobObject(job, 9, ref info, Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            job.Dispose();
            return null;
        }
        return job;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JobObjectExtendedLimitInformation info, int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeProcessHandle process);
}
