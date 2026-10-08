using Downpour.Service;

namespace Downpour.Tests;

public sealed class PhysicalDiskCounterReaderTests
{
    [Fact]
    public async Task ReportsIndividualPhysicalDisksNotOnlyTheTotal()
    {
        using var reader = new PhysicalDiskCounterReader();
        reader.Read(); // the first PDH sample only primes rate counters
        await Task.Delay(1100);
        var (totalRead, _, disks) = reader.Read();
        if (totalRead is null) return; // performance counters disabled on this machine
        Assert.Contains(disks, d => !string.Equals(d.InstanceName, "_Total", StringComparison.OrdinalIgnoreCase));
    }
}
