using Downpour.Service;

namespace Downpour.Tests;

public sealed class DriverInventoryProviderTests
{
    [Fact]
    public void CaptureReturnsBoundedInventoryWithExplicitUnavailableWarnings()
    {
        var snapshot = new DriverInventoryProvider().Capture();

        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.True(snapshot.DriverCount >= snapshot.Drivers.Count);
        Assert.InRange(snapshot.Drivers.Count, 0, 512);
        Assert.All(snapshot.Drivers, driver =>
        {
            Assert.InRange(driver.Name.Length, 1, 512);
            Assert.InRange(driver.ImagePath.Length, 0, 512);
        });
        Assert.NotNull(snapshot.Warnings);
    }
}
