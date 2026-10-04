using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class WindowsServiceInventoryProviderTests
{
    [Fact]
    public void CaptureReturnsBoundedServiceStateAndStartupInventory()
    {
        var snapshot = new WindowsServiceInventoryProvider().Capture();

        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.Contains(snapshot.CollectionStatus, new[] { "Available", "Partial", "Access denied", "Unavailable" });
        Assert.Equal(snapshot.Services.Count, snapshot.ServiceCount);
        Assert.InRange(snapshot.Services.Count, 0, WindowsServiceInventoryProvider.MaximumServices);
        Assert.InRange(snapshot.Warnings.Count, 0, 64);
        Assert.All(snapshot.Services, service =>
        {
            Assert.InRange(service.ServiceName.Length, 1, 256);
            Assert.InRange(service.DisplayName.Length, 1, 256);
            Assert.Contains(service.State, new[] { "Stopped", "Start pending", "Stop pending", "Running", "Continue pending", "Pause pending", "Paused", "Unknown" });
            Assert.Contains(service.StartupType, new[] { "Boot", "System", "Automatic", "Manual", "Disabled", "Access denied", "Unknown" });
        });
        Assert.All(snapshot.Warnings, warning => Assert.InRange(warning.Length, 1, 512));

        if (snapshot.CollectionStatus is "Available" or "Partial")
            Assert.Contains(snapshot.Services, service => service.ServiceName.Equals("EventLog", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ClientRejectsInvalidOrDuplicateServiceRows()
    {
        var validRow = new WindowsServiceInventoryEntry("EventLog", "Windows Event Log", "Running", "Automatic");
        var valid = new WindowsServiceInventorySnapshot(1, DateTimeOffset.UtcNow, "Available", 1, [validRow], []);
        Assert.True(WindowsServiceInventoryClient.IsValidSnapshot(valid));

        Assert.False(WindowsServiceInventoryClient.IsValidSnapshot(valid with
        {
            Services = [validRow with { State = "Maybe running" }]
        }));
        Assert.False(WindowsServiceInventoryClient.IsValidSnapshot(valid with
        {
            Services = [validRow, validRow], ServiceCount = 2
        }));
        Assert.False(WindowsServiceInventoryClient.IsValidSnapshot(valid with { CollectionStatus = "Healthy" }));
        Assert.False(WindowsServiceInventoryClient.IsValidSnapshot(valid with
        {
            Services = [validRow with { StartupType = new string('x', 257) }]
        }));
    }
}
