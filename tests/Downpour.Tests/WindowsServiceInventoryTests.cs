using Downpour.Service;

namespace Downpour.Tests;

public sealed class WindowsServiceInventoryTests
{
    [Fact]
    public void InventoryComparesScmAndRegistryWithoutFailing()
    {
        var snapshot = new WindowsServiceInventoryProvider().Capture();
        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.InRange(snapshot.ServiceCount, 0, WindowsServiceInventoryProvider.MaximumServices);
        Assert.True(snapshot.Warnings.Count <= 16);
        Assert.All(snapshot.Warnings, warning =>
        {
            Assert.False(string.IsNullOrWhiteSpace(warning));
            Assert.True(warning.Length <= 1_024);
        });
        Assert.Equal(snapshot.Services.Count, snapshot.ServiceCount);
    }
}
