using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class ServiceRiskAnalyzerTests
{
    private static readonly Func<string, bool> NothingWritable = _ => false;

    [Theory]
    [InlineData("RemoteRegistry", "Manual", "High")]
    [InlineData("RemoteRegistry", "Automatic", "High")]
    [InlineData("RemoteRegistry", "Disabled", "Low")]
    [InlineData("TlntSvr", "Automatic", "High")]
    public void V29SuspiciousServiceNames(string name, string startup, string level)
    {
        var risk = ServiceRiskAnalyzer.Analyze(name, @"C:\Windows\system32\svchost.exe -k localService", startup, NothingWritable);
        Assert.Equal(level, risk.Level);
        Assert.NotEmpty(risk.Indicators);
    }

    [Theory]
    [InlineData("AnyDesk", @"""C:\Program Files (x86)\AnyDesk\AnyDesk.exe"" --service", "Medium")]
    [InlineData("WinRM", @"C:\Windows\System32\svchost.exe -k NetworkService -p", "High")]
    [InlineData("ngrokd", @"C:\tools\x.exe", "High")]
    [InlineData("Spooler", @"C:\Windows\System32\spoolsv.exe", "Clean")]
    public void V29RemoteAccessVectorsUseSubstringMatching(string name, string imagePath, string level) =>
        Assert.Equal(level, ServiceRiskAnalyzer.Analyze(name, imagePath, "Manual", NothingWritable).Level);

    [Fact]
    public void KernelDriversDoNotMatchRemoteAccessVectors()
    {
        Assert.Equal("Clean", ServiceRiskAnalyzer.Analyze("rdpbus", @"\SystemRoot\System32\drivers\rdpbus.sys", "Manual", NothingWritable).Level);
        Assert.Equal("Clean", ServiceRiskAnalyzer.Analyze("RDPDR", @"System32\drivers\rdpdr.sys", "Manual", NothingWritable).Level);
    }

    [Fact]
    public void LiveStartupTypesAreReadFromTheCorrectStructField()
    {
        // Regression: QUERY_SERVICE_CONFIGW was declared out of order, so every service read as "Boot".
        var services = new WindowsServiceInventoryProvider().Capture().Services;
        Assert.Contains(services, service => service.StartupType == "Automatic");
        Assert.Contains(services, service => service.StartupType == "Manual");
        Assert.True(services.Count(service => service.StartupType == "Boot") < services.Count / 4);
        var eventLog = services.FirstOrDefault(service => service.ServiceName.Equals("EventLog", StringComparison.OrdinalIgnoreCase));
        if (eventLog is not null) Assert.Equal("Automatic", eventLog.StartupType);
    }

    [Fact]
    public void UnquotedPathWithSpacesIsMediumOrHighWhenPlantable()
    {
        const string path = @"C:\Program Files\Vendor Tool\svc.exe -run";
        Assert.True(ServiceRiskAnalyzer.IsUnquotedWithSpaces(path));
        Assert.Equal(["C:\\", @"C:\Program Files"], ServiceRiskAnalyzer.UnquotedCandidateDirectories(path).ToArray());

        Assert.Equal("Medium", ServiceRiskAnalyzer.Analyze("VendorSvc", path, "Automatic", NothingWritable).Level);
        var plantable = ServiceRiskAnalyzer.Analyze("VendorSvc", path, "Automatic", directory => directory == @"C:\Program Files");
        Assert.Equal("High", plantable.Level);
        Assert.Contains(plantable.Indicators, indicator => indicator.Contains(@"C:\Program Files"));
    }

    [Theory]
    [InlineData(@"""C:\Program Files\App\app.exe"" -k", false)]
    [InlineData(@"C:\Windows\System32\svchost.exe -k netsvcs", false)]
    [InlineData(@"\SystemRoot\System32\drivers\acpi.sys", false)]
    [InlineData(@"system32\drivers\x.sys", false)]
    [InlineData(@"C:\My Apps\svc.exe", true)]
    public void UnquotedDetection(string path, bool expected) =>
        Assert.Equal(expected, ServiceRiskAnalyzer.IsUnquotedWithSpaces(path));

    [Fact]
    public void ExecutablePathHandlesQuotedRootedAndDriverForms()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.Equal(@"C:\Program Files\App\app.exe", ServiceRiskAnalyzer.ExecutablePath(@"""C:\Program Files\App\app.exe"" --service"));
        Assert.Equal(Path.Combine(windows, @"System32\drivers\acpi.sys"), ServiceRiskAnalyzer.ExecutablePath(@"\SystemRoot\System32\drivers\acpi.sys"));
        Assert.Equal(Path.Combine(windows, @"system32\drivers\x.sys"), ServiceRiskAnalyzer.ExecutablePath(@"system32\drivers\x.sys"));
        Assert.Equal(@"C:\Windows\System32\svchost.exe", ServiceRiskAnalyzer.ExecutablePath(@"C:\Windows\System32\svchost.exe -k netsvcs"));
        Assert.Equal("", ServiceRiskAnalyzer.ExecutablePath(""));
    }

    [Fact]
    public void WritableOrStagingBinaryFolderIsHigh()
    {
        Assert.Equal("High", ServiceRiskAnalyzer.Analyze("Updater", @"C:\Users\a\AppData\Local\Temp\u.exe", "Automatic", NothingWritable).Level);
        var writable = ServiceRiskAnalyzer.Analyze("Agent", @"""C:\Tools\agent.exe""", "Automatic", directory => directory == @"C:\Tools");
        Assert.Equal("High", writable.Level);
        Assert.Equal("Medium", ServiceRiskAnalyzer.Analyze("Agent", @"""C:\Tools\agent.exe""", "Disabled", directory => directory == @"C:\Tools").Level);
    }

    [Fact]
    public void LiveInventoryHasPlausibleRiskDistribution()
    {
        var snapshot = new WindowsServiceInventoryProvider().Capture();
        Assert.True(WindowsServiceInventoryClient.IsValidSnapshot(snapshot));
        Assert.All(snapshot.Services, service => Assert.Contains(service.Risk, ServiceRiskAnalyzer.Levels));
        Assert.Contains(snapshot.Services, service => service.ImagePath.Length > 0);
        // Most services on a healthy machine are clean.
        Assert.True(snapshot.Services.Count(service => service.Risk == ServiceRiskAnalyzer.Clean) > snapshot.Services.Count / 2);
        // System32 is never writable by standard users.
        Assert.False(FileSystemExposure.IsWritableByStandardUsers(Environment.GetFolderPath(Environment.SpecialFolder.System)));
    }

    [Fact]
    public void ClientRejectsUnknownRiskLevels()
    {
        var entry = new WindowsServiceInventoryEntry("Svc", "Service", "Running", "Automatic", "C:\\x.exe", "High", ["reason"]);
        var good = new WindowsServiceInventorySnapshot(1, DateTimeOffset.UtcNow, "Available", 1, [entry], []);
        Assert.True(WindowsServiceInventoryClient.IsValidSnapshot(good));
        Assert.False(WindowsServiceInventoryClient.IsValidSnapshot(good with { Services = [entry with { Risk = "Severe" }] }));
        Assert.False(WindowsServiceInventoryClient.IsValidSnapshot(good with { Services = [entry with { RiskIndicators = Enumerable.Repeat("x", 9).ToArray() }] }));
        // Older snapshots without risk fields still validate.
        Assert.True(WindowsServiceInventoryClient.IsValidSnapshot(good with { Services = [new WindowsServiceInventoryEntry("Svc", "Service", "Running", "Automatic")] }));
    }
}
