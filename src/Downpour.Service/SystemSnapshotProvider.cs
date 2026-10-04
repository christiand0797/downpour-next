using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Downpour.Contracts;

namespace Downpour.Service;

public sealed class SystemSnapshotProvider
{
    public const int MaximumProcessRows = 512;
    public const int MaximumProcessNameLength = 128;
    private ulong? _previousIdle;
    private ulong? _previousKernel;
    private ulong? _previousUser;

    public SystemHealthSnapshot Capture()
    {
        var warnings = new List<string>();
        var processCount = 0;
        var processes = new List<ProcessSnapshot>();
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
                    processes.Add(new ProcessSnapshot(
                        processId,
                        processName[..Math.Min(processName.Length, MaximumProcessNameLength)],
                        process.WorkingSet64,
                        process.Threads.Count));
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

        var memoryTotal = 0UL;
        var memoryAvailable = 0UL;
        var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
        if (GlobalMemoryStatusEx(ref memory))
        {
            memoryTotal = memory.TotalPhysical;
            memoryAvailable = memory.AvailablePhysical;
        }
        else
        {
            warnings.Add("Physical memory counters are unavailable.");
        }

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
        return new SystemHealthSnapshot(
            1,
            DateTimeOffset.UtcNow,
            processCount,
            cpuPercent,
            memoryTotal,
            memoryAvailable,
            activeConnections,
            processes.OrderByDescending(process => process.WorkingSetBytes).Take(MaximumProcessRows).ToArray(),
            warnings);
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus buffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out SystemFileTime idleTime, out SystemFileTime kernelTime, out SystemFileTime userTime);
}
