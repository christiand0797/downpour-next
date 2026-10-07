using System.Runtime.InteropServices;

namespace Downpour.Service;

public sealed record GpuThermalReading(double? GpuPercent, ulong? GpuDedicatedBytes, ulong? GpuSharedBytes, double? ThermalZoneCelsius);

/// <summary>
/// Reads GPU utilization, GPU memory in use, and ACPI thermal-zone temperature from locale-independent Windows
/// performance counters (no administrator rights, no WMI, no vendor SDKs).
/// GPU utilization follows Task Manager: engine utilization is summed per engine type across processes, and the busiest
/// engine type is reported. Thermal zones are firmware sensors (often the motherboard), not necessarily the CPU die.
/// </summary>
internal sealed class GpuThermalCounterReader : IDisposable
{
    private const uint FormatDouble = 0x00000200;
    private const uint ValidData = 0;
    private const uint NewData = 1;
    private const uint MoreData = 0x800007D2;
    private const int MaximumItems = 8192;
    private IntPtr _query;
    private IntPtr _engine;
    private IntPtr _dedicated;
    private IntPtr _shared;
    private IntPtr _thermal;
    private bool _primed;
    private bool _disposed;

    public GpuThermalCounterReader()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            if (PdhOpenQueryW(IntPtr.Zero, UIntPtr.Zero, out _query) != 0) { _query = IntPtr.Zero; return; }
            // Each counter is optional: machines without a WDDM 2.x GPU or without ACPI thermal zones simply lack it.
            if (PdhAddEnglishCounterW(_query, @"\GPU Engine(*)\Utilization Percentage", UIntPtr.Zero, out _engine) != 0) _engine = IntPtr.Zero;
            if (PdhAddEnglishCounterW(_query, @"\GPU Adapter Memory(*)\Dedicated Usage", UIntPtr.Zero, out _dedicated) != 0) _dedicated = IntPtr.Zero;
            if (PdhAddEnglishCounterW(_query, @"\GPU Adapter Memory(*)\Shared Usage", UIntPtr.Zero, out _shared) != 0) _shared = IntPtr.Zero;
            if (PdhAddEnglishCounterW(_query, @"\Thermal Zone Information(*)\Temperature", UIntPtr.Zero, out _thermal) != 0) _thermal = IntPtr.Zero;
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            _query = IntPtr.Zero;
        }
    }

    public GpuThermalReading Read()
    {
        if (_disposed || _query == IntPtr.Zero) return new(null, null, null, null);
        try
        {
            if (PdhCollectQueryData(_query) != 0) return new(null, null, null, null);
            if (!_primed)
            {
                // Rate counters (engine utilization) need two samples.
                _primed = true;
                return new(null, ReadSum(_dedicated), ReadSum(_shared), ReadThermal());
            }
            return new(ReadGpuPercent(), ReadSum(_dedicated), ReadSum(_shared), ReadThermal());
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            Dispose();
            return new(null, null, null, null);
        }
    }

    private double? ReadGpuPercent()
    {
        var items = ReadArray(_engine);
        if (items is null || items.Count == 0) return null;
        return BusiestEnginePercent(items);
    }

    /// <summary>
    /// Instance names look like "pid_1234_luid_0x..._0x..._phys_0_eng_3_engtype_3D". Each physical engine
    /// (adapter LUID + engine index) is summed across processes, and the busiest engine is reported, as Task Manager does.
    /// Grouping by engine type alone would add up engines from different GPUs.
    /// </summary>
    internal static double? BusiestEnginePercent(IReadOnlyList<(string Name, double Value)> items)
    {
        var byEngine = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in items)
        {
            var start = name.IndexOf("luid_", StringComparison.OrdinalIgnoreCase);
            var end = name.IndexOf("_engtype_", StringComparison.OrdinalIgnoreCase);
            var engine = start >= 0 && end > start ? name[start..end] : name;
            byEngine[engine] = byEngine.GetValueOrDefault(engine) + value;
        }
        return byEngine.Count == 0 ? null : Math.Clamp(byEngine.Values.Max(), 0, 100);
    }

    private ulong? ReadSum(IntPtr counter)
    {
        var items = ReadArray(counter);
        if (items is null || items.Count == 0) return null;
        var total = items.Sum(item => item.Value);
        return total is >= 0 and < 1e15 ? (ulong)total : null;
    }

    private double? ReadThermal()
    {
        var items = ReadArray(_thermal);
        if (items is null || items.Count == 0) return null;
        // The counter reports Kelvin. Keep only physically plausible readings (0..125 °C).
        var celsius = items.Select(item => item.Value - 273.15).Where(value => value is > 0 and < 125).ToArray();
        return celsius.Length == 0 ? null : Math.Round(celsius.Max(), 1);
    }

    private static List<(string Name, double Value)>? ReadArray(IntPtr counter)
    {
        if (counter == IntPtr.Zero) return null;
        uint size = 0;
        var status = PdhGetFormattedCounterArrayW(counter, FormatDouble, ref size, out var count, IntPtr.Zero);
        if (status != MoreData || size == 0 || count == 0 || count > MaximumItems) return null;
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (PdhGetFormattedCounterArrayW(counter, FormatDouble, ref size, out count, buffer) != 0) return null;
            var itemSize = Marshal.SizeOf<CounterValueItem>();
            var result = new List<(string, double)>((int)Math.Min(count, MaximumItems));
            for (var i = 0; i < count && i < MaximumItems; i++)
            {
                var item = Marshal.PtrToStructure<CounterValueItem>(buffer + i * itemSize);
                if (item.CStatus is not (ValidData or NewData) || !double.IsFinite(item.DoubleValue) || item.DoubleValue < 0) continue;
                result.Add((Marshal.PtrToStringUni(item.Name) ?? "", item.DoubleValue));
            }
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_query != IntPtr.Zero) PdhCloseQuery(_query);
        _query = IntPtr.Zero;
    }

    // PDH_FMT_COUNTERVALUE_ITEM_W: { LPWSTR szName; PDH_FMT_COUNTERVALUE FmtValue { DWORD CStatus; union { ... double } } }
    [StructLayout(LayoutKind.Sequential)]
    private struct CounterValueItem
    {
        public IntPtr Name;
        public uint CStatus;
        public double DoubleValue;
    }

    [DllImport("pdh.dll", EntryPoint = "PdhOpenQueryW")]
    private static extern uint PdhOpenQueryW(IntPtr dataSource, UIntPtr userData, out IntPtr query);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhAddEnglishCounterW")]
    private static extern uint PdhAddEnglishCounterW(IntPtr query, string fullCounterPath, UIntPtr userData, out IntPtr counter);

    [DllImport("pdh.dll", EntryPoint = "PdhCollectQueryData")]
    private static extern uint PdhCollectQueryData(IntPtr query);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhGetFormattedCounterArrayW")]
    private static extern uint PdhGetFormattedCounterArrayW(IntPtr counter, uint format, ref uint bufferSize, out uint itemCount, IntPtr itemBuffer);

    [DllImport("pdh.dll", EntryPoint = "PdhCloseQuery")]
    private static extern uint PdhCloseQuery(IntPtr query);
}
