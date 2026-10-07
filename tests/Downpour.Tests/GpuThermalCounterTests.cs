using Downpour.Service;

namespace Downpour.Tests;

public sealed class GpuThermalCounterTests
{
    [Fact]
    public void BusiestEngineSumsProcessesPerEngineAndKeepsGpusSeparate()
    {
        var items = new List<(string, double)>
        {
            // GPU A, 3D engine 0: two processes share it -> 30 + 25 = 55
            ("pid_10_luid_0x00000000_0x0000f50d_phys_0_eng_0_engtype_3D", 30),
            ("pid_11_luid_0x00000000_0x0000f50d_phys_0_eng_0_engtype_3D", 25),
            // GPU B, 3D engine 0: 40. Grouping by engine type alone would wrongly report 95.
            ("pid_12_luid_0x00000000_0x0001072a_phys_0_eng_0_engtype_3D", 40),
            // GPU A, video decode engine: 10
            ("pid_10_luid_0x00000000_0x0000f50d_phys_0_eng_5_engtype_VideoDecode", 10),
        };
        Assert.Equal(55, GpuThermalCounterReader.BusiestEnginePercent(items));
    }

    [Fact]
    public void BusiestEngineIsClampedAndEmptyIsUnknown()
    {
        Assert.Null(GpuThermalCounterReader.BusiestEnginePercent([]));
        Assert.Equal(100, GpuThermalCounterReader.BusiestEnginePercent([("pid_1_luid_0x0_0x1_phys_0_eng_0_engtype_3D", 140)]));
    }

    [Fact]
    public void LiveReaderReturnsPlausibleValuesOrNothing()
    {
        using var reader = new GpuThermalCounterReader();
        reader.Read();
        Thread.Sleep(1100);
        var reading = reader.Read();
        Assert.True(reading.GpuPercent is null or (>= 0 and <= 100));
        Assert.True(reading.ThermalZoneCelsius is null or (> 0 and < 125));
    }
}
