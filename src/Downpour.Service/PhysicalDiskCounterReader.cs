using System.Runtime.InteropServices;

namespace Downpour.Service;

/// <summary>Reads locale-independent Windows PhysicalDisk(_Total) throughput counters.</summary>
internal sealed class PhysicalDiskCounterReader : IDisposable
{
    private const uint FormatDouble = 0x00000200;
    private const uint ValidData = 0;
    private const uint NewData = 1;
    private IntPtr _query;
    private IntPtr _readCounter;
    private IntPtr _writeCounter;
    private bool _initialized;
    private bool _disposed;

    public PhysicalDiskCounterReader()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            if (PdhOpenQueryW(IntPtr.Zero, UIntPtr.Zero, out _query) != 0) return;
            if (PdhAddEnglishCounterW(_query, @"\PhysicalDisk(_Total)\Disk Read Bytes/sec", UIntPtr.Zero, out _readCounter) != 0 ||
                PdhAddEnglishCounterW(_query, @"\PhysicalDisk(_Total)\Disk Write Bytes/sec", UIntPtr.Zero, out _writeCounter) != 0)
                Dispose();
        }
        catch (DllNotFoundException) { Dispose(); }
        catch (EntryPointNotFoundException) { Dispose(); }
    }

    public (long? ReadBytesPerSecond, long? WriteBytesPerSecond) Read()
    {
        if (_disposed || _query == IntPtr.Zero || _readCounter == IntPtr.Zero || _writeCounter == IntPtr.Zero)
            return (null, null);
        try
        {
            if (PdhCollectQueryData(_query) != 0) return (null, null);
            if (!_initialized)
            {
                _initialized = true;
                return (null, null);
            }
            return (ReadCounter(_readCounter), ReadCounter(_writeCounter));
        }
        catch (DllNotFoundException) { Dispose(); return (null, null); }
        catch (EntryPointNotFoundException) { Dispose(); return (null, null); }
    }

    private static long? ReadCounter(IntPtr counter)
    {
        if (PdhGetFormattedCounterValue(counter, FormatDouble, out _, out var value) != 0 ||
            value.CStatus is not (ValidData or NewData) || !double.IsFinite(value.DoubleValue) ||
            value.DoubleValue < 0 || value.DoubleValue > long.MaxValue)
            return null;
        return (long)Math.Round(value.DoubleValue, MidpointRounding.AwayFromZero);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_query != IntPtr.Zero) PdhCloseQuery(_query);
        _query = IntPtr.Zero;
        _readCounter = IntPtr.Zero;
        _writeCounter = IntPtr.Zero;
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
}
