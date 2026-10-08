using System.Runtime.InteropServices;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Reads locale-independent Windows PhysicalDisk throughput counters.</summary>
internal sealed class PhysicalDiskCounterReader : IDisposable
{
    private const uint FormatDouble = 0x00000200;
    private const uint ValidData = 0;
    private const uint NewData = 1;
    private IntPtr _query;
    private readonly Dictionary<string, (IntPtr ReadCounter, IntPtr WriteCounter)> _diskCounters = new();
    private readonly List<string> _diskInstances = new();
    private bool _initialized;
    private bool _disposed;

    private const uint PerfDetailWizard = 400;

    public PhysicalDiskCounterReader()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            if (PdhOpenQueryW(IntPtr.Zero, UIntPtr.Zero, out _query) != 0) return;

            // Enumerate physical disk instances - first call to get buffer sizes
            uint counterBufferSize = 0;
            uint instanceBufferSize = 0;
            if (PdhEnumObjectItemsW(IntPtr.Zero, IntPtr.Zero, "PhysicalDisk", IntPtr.Zero, ref counterBufferSize, IntPtr.Zero, ref instanceBufferSize, PerfDetailWizard, 0) != 0)
            {
                // Allocate buffers
                // PDH reports both sizes in characters, not bytes.
                var counterBuffer = Marshal.AllocHGlobal((int)Math.Max(2, counterBufferSize) * sizeof(char));
                var instanceBuffer = Marshal.AllocHGlobal((int)Math.Max(2, instanceBufferSize) * sizeof(char));
                try
                {
                    if (PdhEnumObjectItemsW(IntPtr.Zero, IntPtr.Zero, "PhysicalDisk", counterBuffer, ref counterBufferSize, instanceBuffer, ref instanceBufferSize, PerfDetailWizard, 0) != 0)
                    {
                        Dispose();
                        return;
                    }

                    // Parse the multi-sz string to get instances
                    var instances = ParseMultiSz(instanceBuffer, instanceBufferSize * sizeof(char));
                    foreach (var instance in instances)
                    {
                        if (string.Equals(instance, "_Total", StringComparison.OrdinalIgnoreCase)) continue;
                        var readPath = $@"\PhysicalDisk({instance})\Disk Read Bytes/sec";
                        var writePath = $@"\PhysicalDisk({instance})\Disk Write Bytes/sec";
                        if (PdhAddEnglishCounterW(_query, readPath, UIntPtr.Zero, out var readCounter) == 0 &&
                            PdhAddEnglishCounterW(_query, writePath, UIntPtr.Zero, out var writeCounter) == 0)
                        {
                            _diskCounters[instance] = (readCounter, writeCounter);
                            _diskInstances.Add(instance);
                        }
                    }

                    // Also add _Total for aggregate
                    if (PdhAddEnglishCounterW(_query, @"\PhysicalDisk(_Total)\Disk Read Bytes/sec", UIntPtr.Zero, out var totalReadCounter) == 0 &&
                        PdhAddEnglishCounterW(_query, @"\PhysicalDisk(_Total)\Disk Write Bytes/sec", UIntPtr.Zero, out var totalWriteCounter) == 0)
                    {
                        _diskCounters["_Total"] = (totalReadCounter, totalWriteCounter);
                        if (!_diskInstances.Contains("_Total")) _diskInstances.Insert(0, "_Total");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(counterBuffer);
                    Marshal.FreeHGlobal(instanceBuffer);
                }
            }
        }
        catch (DllNotFoundException) { Dispose(); }
        catch (EntryPointNotFoundException) { Dispose(); }
    }

    public (long? ReadBytesPerSecond, long? WriteBytesPerSecond, IReadOnlyList<PhysicalDiskSnapshot> PhysicalDisks) Read()
    {
        if (_disposed || _query == IntPtr.Zero)
            return (null, null, Array.Empty<PhysicalDiskSnapshot>());

        try
        {
            if (PdhCollectQueryData(_query) != 0) return (null, null, Array.Empty<PhysicalDiskSnapshot>());

            var disks = new List<PhysicalDiskSnapshot>();
            long? totalRead = null;
            long? totalWrite = null;

            foreach (var instance in _diskInstances)
            {
                if (!_diskCounters.TryGetValue(instance, out var counters)) continue;

                var read = ReadCounter(counters.ReadCounter);
                var write = ReadCounter(counters.WriteCounter);
                disks.Add(new PhysicalDiskSnapshot(instance, read, write));

                if (string.Equals(instance, "_Total", StringComparison.OrdinalIgnoreCase))
                {
                    totalRead = read;
                    totalWrite = write;
                }
            }

            if (!_initialized)
            {
                _initialized = true;
                return (null, null, Array.Empty<PhysicalDiskSnapshot>());
            }

            return (totalRead, totalWrite, disks);
        }
        catch (DllNotFoundException) { Dispose(); return (null, null, Array.Empty<PhysicalDiskSnapshot>()); }
        catch (EntryPointNotFoundException) { Dispose(); return (null, null, Array.Empty<PhysicalDiskSnapshot>()); }
    }

    private static long? ReadCounter(IntPtr counter)
    {
        if (PdhGetFormattedCounterValue(counter, FormatDouble, out _, out var value) != 0 ||
            value.CStatus is not (ValidData or NewData) || !double.IsFinite(value.DoubleValue) ||
            value.DoubleValue < 0 || value.DoubleValue > long.MaxValue)
            return null;
        return (long)Math.Round(value.DoubleValue, MidpointRounding.AwayFromZero);
    }

    private static List<string> ParseMultiSz(IntPtr buffer, uint size)
    {
        var result = new List<string>();
        var current = new System.Text.StringBuilder();
        for (int i = 0; i < size; i += 2)
        {
            if (i + 1 >= size) break;
            var c = Marshal.ReadInt16(buffer, i);
            if (c == 0)
            {
                if (current.Length > 0)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    break; // Double null terminates
                }
            }
            else
            {
                current.Append((char)c);
            }
        }
        return result;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_query != IntPtr.Zero) PdhCloseQuery(_query);
        _query = IntPtr.Zero;
        _diskCounters.Clear();
        _diskInstances.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FormattedCounterValue
    {
        public uint CStatus;
        public double DoubleValue;
    }

    [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhOpenQueryW")]
    private static extern uint PdhOpenQueryW(IntPtr dataSource, UIntPtr userData, out IntPtr query);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhAddEnglishCounterW")]
    private static extern uint PdhAddEnglishCounterW(IntPtr query, string fullCounterPath, UIntPtr userData, out IntPtr counter);

    [DllImport("pdh.dll", EntryPoint = "PdhCollectQueryData")]
    private static extern uint PdhCollectQueryData(IntPtr query);

    [DllImport("pdh.dll", EntryPoint = "PdhGetFormattedCounterValue")]
    private static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, out uint counterType, out FormattedCounterValue value);

    [DllImport("pdh.dll", EntryPoint = "PdhCloseQuery")]
    private static extern uint PdhCloseQuery(IntPtr query);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhEnumObjectItemsW")]
    private static extern uint PdhEnumObjectItemsW(IntPtr dataSource, IntPtr machineName, string objectName, IntPtr counterBuffer, ref uint counterBufferSize, IntPtr instanceBuffer, ref uint instanceBufferSize, uint detailLevel, uint flags);
}