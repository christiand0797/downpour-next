using Downpour.Service;

namespace Downpour.Tests;

public sealed class DriverInventoryTests
{
    [Fact]
    public void DriverInventoryStaysBoundedAndDoesNotFail()
    {
        var snapshot = new DriverInventoryProvider().Capture();
        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.True(snapshot.Drivers.Count <= 512);
        Assert.True(snapshot.DriverCount >= 0);

        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "driver-warnings.txt"), string.Join(Environment.NewLine, snapshot.Warnings));
        Assert.True(snapshot.Warnings.Count <= 16);
        Assert.All(snapshot.Warnings, warning =>
        {
            Assert.False(string.IsNullOrWhiteSpace(warning));
            Assert.True(warning.Length <= 1_024);
        });
    }
}
