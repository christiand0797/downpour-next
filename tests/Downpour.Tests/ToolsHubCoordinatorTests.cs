using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class ToolsHubCoordinatorTests
{
    [Fact]
    public void GetSnapshot_AggregatesNineOperationalTools()
    {
        var coordinator = new ToolsHubCoordinator();
        var snapshot = coordinator.GetSnapshot();

        Assert.NotNull(snapshot);
        Assert.Equal(9, snapshot.TotalTools);
        Assert.Equal(9, snapshot.Tools.Count);
        Assert.NotEmpty(snapshot.OperationalHealth);

        var routeIds = snapshot.Tools.Select(t => t.RouteId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("remote-access", routeIds);
        Assert.Contains("vpn", routeIds);
        Assert.Contains("parental-controls", routeIds);
        Assert.Contains("emergency", routeIds);
        Assert.Contains("cleanup", routeIds);
        Assert.Contains("usb", routeIds);
        Assert.Contains("iot", routeIds);
        Assert.Contains("services", routeIds);
        Assert.Contains("settings", routeIds);

        foreach (var tool in snapshot.Tools)
        {
            Assert.False(string.IsNullOrWhiteSpace(tool.Title));
            Assert.False(string.IsNullOrWhiteSpace(tool.Category));
            Assert.False(string.IsNullOrWhiteSpace(tool.Status));
            Assert.False(string.IsNullOrWhiteSpace(tool.Summary));
            Assert.False(string.IsNullOrWhiteSpace(tool.TelemetryLabel));
            Assert.False(string.IsNullOrWhiteSpace(tool.TelemetryValue));
            Assert.False(string.IsNullOrWhiteSpace(tool.Glyph));
        }
    }

    [Fact]
    public void RunSystemDiagnostics_ReturnsValidSystemChecks()
    {
        var diagnostics = ToolsHubCoordinator.RunSystemDiagnostics();

        Assert.NotNull(diagnostics);
        Assert.NotEmpty(diagnostics);
        Assert.True(diagnostics.Count >= 3);

        var osCheck = diagnostics.FirstOrDefault(d => d.Name == "Host Platform");
        Assert.NotNull(osCheck);
        Assert.True(osCheck.IsPassed);
        Assert.NotEmpty(osCheck.ObservedValue);
    }

    [Fact]
    public void GenerateToolsHubReport_FormatsExecutiveReportCorrectly()
    {
        var coordinator = new ToolsHubCoordinator();
        var snapshot = coordinator.GetSnapshot();

        string report = coordinator.GenerateToolsHubReport(snapshot);

        Assert.Contains("# Operational Tools & Diagnostics Launchpad Report", report);
        Assert.Contains("Operational Security Subsystems", report);
        Assert.Contains("System Diagnostic Health Checks", report);
        Assert.Contains("Remote Access Monitor", report);
        Assert.Contains("VPN & Tunnel Posture", report);
        Assert.Contains("Parental & Family Safety", report);
        Assert.Contains("Emergency Response Center", report);
        Assert.Contains("System & Disk Cleanup", report);
        Assert.Contains("USB Device Controller", report);
        Assert.Contains("IoT & Subnet Discovery", report);
        Assert.Contains("Windows Services Inventory", report);
        Assert.Contains("Application Preferences", report);
    }
}
