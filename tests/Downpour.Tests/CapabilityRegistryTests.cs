using Downpour.Core;

namespace Downpour.Tests;

public sealed class CapabilityRegistryTests
{
    [Fact]
    public void RegistryPreservesOriginalRoutesAndAddsUniqueDriverRoute()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "capabilities.json");

        var capabilities = CapabilityRegistry.Load(path);

        Assert.Equal(34, capabilities.Count);
        Assert.Equal(capabilities.Count, capabilities.Select(item => item.RouteId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(capabilities.Count, capabilities.Select(item => item.Title).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains(capabilities, item => item.RouteId == "dashboard" && item.Status == "prototype");
        Assert.Contains(capabilities, item => item.RouteId == "processes" && item.Status == "in-progress");
        Assert.Contains(capabilities, item => item.RouteId == "drivers" && item.Status == "in-progress");
    }
}
