using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Management;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Reads system-wide performance counters and process inventory.</summary>
public sealed class SystemSnapshotProvider : IDisposable
{
    public const int MaximumProcessRows = 512;
    public const int MaximumProcessNameLength = 128;
    private ulong? _previousIdle;
    private ulong? _previousKernel;
    private ulong? _previousUser;
    private Dictionary<int, ProcessCpuSample> _previousProcessCpu = [];
    private readonly PhysicalDiskCounterReader _diskCounters = new();

    public SystemHealthSnapshot Capture()
    {
        var warnings = new List<string>();
        var processCount = 0;
        var processes = new List<ProcessSnapshot>();
        var currentProcessCpu = new Dictionary<int, ProcessCpuSample>();
        var capturedTimestamp = Stopwatch.GetTimestamp();
        var processorCount = Math.Max(1, Environment.ProcessorCount);
        try
        {
            var running = Process.GetProcesses();
            processCount = running.Length;
            foreach (var process in running)
            {
                try
                {
                    var processId = process.Id;
                    if (processId <= 0) continue;
                    var processName = process.ProcessName;
                    double? processCpuPercent = null;
                    try
                    {
                        var cpuTicks = process.TotalProcessorTime.Ticks;
                        var startTimeTicks = process.StartTime.ToUniversalTime().Ticks;
                        var current = new ProcessCpuSample(cpuTicks, startTimeTicks, capturedTimestamp);
                        if (_previousProcessCpu.TryGetValue(processId, out var previous) && previous.StartTimeUtcTicks == startTimeTicks)
                        {
                            var elapsed = Stopwatch.GetElapsedTime(previous.CapturedTimestamp, capturedTimestamp);
                            processCpuPercent = CalculateProcessCpuPercent(previous.CpuTimeTicks, cpuTicks, elapsed, processorCount);
                        }
                        currentProcessCpu[processId] = current;
                    }
                    catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException or UnauthorizedAccessException or ArgumentException)
                    {
                        // Per-process CPU is optional; inaccessible or exiting processes remain unknown.
                    }
                    processes.Add(new ProcessSnapshot(
                        processId,
                        processName[..Math.Min(processName.Length, MaximumProcessNameLength)],
                        process.WorkingSet64,
                        process.Threads.Count,
                        processCpuPercent));
                }
                catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    // Access can disappear while the process list changes; retain the rest of the snapshot.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or NotSupportedException)
        {
            warnings.Add("Process inventory is temporarily unavailable.");
        }
        _previousProcessCpu = currentProcessCpu;

        var memoryTotal = 0UL;
        var memoryAvailable = 0UL;
        ulong? pageFileTotal = null;
        ulong? pageFileAvailable = null;
        var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
        if (GlobalMemoryStatusEx(ref memory))
        {
            memoryTotal = memory.TotalPhysical;
            memoryAvailable = memory.AvailablePhysical;
            pageFileTotal = memory.TotalPageFile > 0 ? memory.TotalPageFile : null;
            pageFileAvailable = memory.AvailablePageFile > 0 ? memory.AvailablePageFile : null;
        }
        else
        {
            warnings.Add("Physical memory counters are unavailable.");
        }

        var (commitLimitBytes, committedBytes) = ReadSystemCommitUsage();
        if (commitLimitBytes is null || committedBytes is null)
            warnings.Add("System-wide memory commit counters are unavailable.");

        var (diskReadBytesPerSecond, diskWriteBytesPerSecond, physicalDisks) = _diskCounters.Read();
        if (diskReadBytesPerSecond is null || diskWriteBytesPerSecond is null)
            warnings.Add("Physical disk throughput counters are warming up or unavailable.");

        int? activeConnections = null;
        try
        {
            activeConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Length;
        }
        catch (Exception exception) when (exception is NetworkInformationException or PlatformNotSupportedException)
        {
            warnings.Add("TCP connection inventory is unavailable.");
        }

        double? cpuPercent = ReadCpuPercent();
        var perCoreCpu = ReadPerCoreCpuPercent();
        return new SystemHealthSnapshot(
            1,
            DateTimeOffset.UtcNow,
            processCount,
            cpuPercent,
            memoryTotal,
            memoryAvailable,
            activeConnections,
            processes.OrderByDescending(process => process.WorkingSetBytes).Take(MaximumProcessRows).ToArray(),
            warnings,
            commitLimitBytes,
            committedBytes,
            diskReadBytesPerSecond,
            diskWriteBytesPerSecond,
            perCoreCpu,
            pageFileTotal,
            pageFileAvailable,
            physicalDisks);
    }

    public void Dispose() => _diskCounters.Dispose();

    private static (ulong? LimitBytes, ulong? CommittedBytes) ReadSystemCommitUsage()
    {
        try
        {
            var info = new PerformanceInformation { Size = (uint)Marshal.SizeOf<PerformanceInformation>() };
            if (!GetPerformanceInfo(ref info, info.Size) || info.PageSize == 0 || info.CommitLimit == 0 || info.CommitTotal > info.CommitLimit)
                return (null, null);
            return (PagesToBytes(info.CommitLimit, info.PageSize), PagesToBytes(info.CommitTotal, info.PageSize));
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return (null, null);
        }
    }

    internal static ulong PagesToBytes(nuint pages, nuint pageSize)
    {
        var pageCount = (ulong)pages;
        var size = (ulong)pageSize;
        return size == 0 ? 0 : pageCount > ulong.MaxValue / size ? ulong.MaxValue : pageCount * size;
    }

    private double? ReadCpuPercent()
    {
        if (!GetSystemTimes(out var idle, out var kernel, out var user)) return null;
        var currentIdle = idle.ToUInt64();
        var currentKernel = kernel.ToUInt64();
        var currentUser = user.ToUInt64();
        var result = _previousIdle is null || _previousKernel is null || _previousUser is null
            ? null
            : CalculateCpuPercent(_previousIdle.Value, _previousKernel.Value, _previousUser.Value, currentIdle, currentKernel, currentUser);
        _previousIdle = currentIdle;
        _previousKernel = currentKernel;
        _previousUser = currentUser;
        return result;
    }

    internal static double? CalculateCpuPercent(ulong previousIdle, ulong previousKernel, ulong previousUser,
        ulong currentIdle, ulong currentKernel, ulong currentUser)
    {
        var idleDelta = currentIdle - previousIdle;
        var totalDelta = (currentKernel - previousKernel) + (currentUser - previousUser);
        if (totalDelta == 0 || idleDelta > totalDelta) return null;
        return Math.Round((totalDelta - idleDelta) * 100d / totalDelta, 1);
    }

    internal static double? CalculateProcessCpuPercent(long previousCpuTicks, long currentCpuTicks, TimeSpan elapsed, int processorCount)
    {
        if (previousCpuTicks < 0 || currentCpuTicks < previousCpuTicks || elapsed <= TimeSpan.Zero || processorCount <= 0) return null;
        var availableCpuTicks = elapsed.Ticks * (double)processorCount;
        if (availableCpuTicks <= 0) return null;
        return Math.Round(Math.Clamp((currentCpuTicks - previousCpuTicks) * 100d / availableCpuTicks, 0, 100), 1);
    }

    private sealed record ProcessCpuSample(long CpuTimeTicks, long StartTimeUtcTicks, long CapturedTimestamp);

    private static double?[]? ReadPerCoreCpuPercent()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name != '_Total'");
            var results = new List<double?>();
            foreach (ManagementObject obj in searcher.Get())
            {
                if (obj["PercentProcessorTime"] is not null && double.TryParse(obj["PercentProcessorTime"].ToString(), out var value))
                {
                    results.Add(Math.Round(value, 1));
                }
            }
            return results.Count > 0 ? results.ToArray() : null;
        }
        catch
        {
            return null;
        }
    }

    private static ulong ToUInt64(SystemFileTime value) => ((ulong)value.High << 32) | value.Low;

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemFileTime
    {
        public uint Low;
        public uint High;
        public readonly ulong ToUInt64() => ((ulong)High << 32) | Low;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PerformanceInformation
    {
        public uint Size;
        public nuint CommitTotal;
        public nuint CommitLimit;
        public nuint CommitPeak;
        public nuint PhysicalTotal;
        public nuint PhysicalAvailable;
        public nuint SystemCache;
        public nuint KernelTotal;
        public nuint KernelPaged;
        public nuint KernelNonpaged;
        public nuint PageSize;
        public uint HandleCount;
        public uint ProcessCount;
        public uint ThreadCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus buffer);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetPerformanceInfo(ref PerformanceInformation performanceInformation, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out SystemFileTime idleTime, out SystemFileTime kernelTime, out SystemFileTime userTime);
}