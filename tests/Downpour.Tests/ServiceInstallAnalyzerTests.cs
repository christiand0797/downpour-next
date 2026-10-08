using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class ServiceInstallAnalyzerTests
{
    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\x.sys", @"%SystemRoot%\System32\drivers\x.sys")]
    [InlineData(@"System32\drivers\x.sys", @"%SystemRoot%\System32\drivers\x.sys")]
    [InlineData(@"\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{A}\MpKslDrv.sys", @"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{A}\MpKslDrv.sys")]
    [InlineData("\"C:\\Program Files\\Vendor\\svc.exe\" -service", @"C:\Program Files\Vendor\svc.exe")]
    [InlineData(@"%SystemRoot%\system32\svchost.exe -k netsvcs -p", @"%SystemRoot%\system32\svchost.exe")]
    [InlineData(@"\\attacker\share\x.exe", null)]
    [InlineData("", null)]
    public void ImagePathsAreNormalizedWithoutArguments(string image, string? expected) =>
        Assert.Equal(expected, ServiceInstallAnalyzer.NormalizeImagePath(image));

    [Theory]
    [InlineData(@"%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat", null, "CRITICAL")]
    [InlineData(@"C:\Windows\System32\drivers\MpKslDrv.sys", "ms", "LOW")]
    [InlineData(@"C:\Program Files\Vendor\svc.exe", "vendor", "MEDIUM")]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\svc.exe", "vendor", "HIGH")]
    [InlineData(@"C:\Program Files\Vendor\svc.exe", "unsigned", "HIGH")]
    [InlineData(@"C:\Program Files\Vendor\svc.exe", null, "HIGH")]
    public void InstallsAreGradedByWhatWasInstalled(string image, string? signer, string severity)
    {
        PersistenceSignature? signature = signer switch
        {
            "ms" => new(true, "Microsoft Windows", true),
            "vendor" => new(true, "CN=Vendor Inc, O=Vendor Inc", false),
            "unsigned" => new(false, null, false),
            _ => null,
        };
        var resolved = ServiceInstallAnalyzer.NormalizeImagePath(image);
        var (actual, detail) = ServiceInstallAnalyzer.Assess("HIGH", "TestSvc", image, resolved, signature);
        Assert.Equal(severity, actual);
        Assert.StartsWith("TestSvc · ", detail, StringComparison.Ordinal);
        Assert.True(detail.Length <= ServiceInstallAnalyzer.MaximumDetail);
        Assert.DoesNotContain("/Q /c echo", detail);
    }

    [Fact]
    public void MissingServiceFilesAreExplainedNotDowngraded()
    {
        var (severity, detail) = ServiceInstallAnalyzer.Assess("HIGH", "Claude", @"C:\Program Files\WindowsApps\Old\svc.exe", null, null);
        Assert.Equal("HIGH", severity);
        Assert.StartsWith("Claude · file no longer exists", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ProviderGradesARealMicrosoftServiceBinaryLow()
    {
        var provider = new SecurityEventProvider(new FileSignatureChecker());
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 1, DateTimeOffset.UtcNow)!;
        var described = provider.Describe(observation, "TestSvc", @"%SystemRoot%\System32\svchost.exe -k netsvcs");
        Assert.Equal("LOW", described.Severity);
        Assert.EndsWith(@"\System32\svchost.exe", described.FilePath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("signed by Microsoft", described.Detail);
        Assert.DoesNotContain("netsvcs", described.Detail);
        Assert.True(SecurityEventClient.IsValidSnapshot(new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, [described], 1, [])));
    }

    [Fact]
    public void ValidatorOnlyLetsServiceInstallsCarryDetailOrRegradedSeverity()
    {
        var now = DateTimeOffset.UtcNow;
        var install = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 1, now)!;
        var logon = SecurityEventProvider.CreateObservation("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager", 21, 2, now)!;
        bool Valid(SecurityEventObservation item) => SecurityEventClient.IsValidSnapshot(new SecurityEventSnapshot(1, now, [item], 1, []));

        Assert.True(Valid(install with { Severity = "LOW", Detail = "svc · C:\\x.sys · signed by Microsoft", FilePath = @"C:\x.sys" }));
        Assert.False(Valid(install with { Severity = "LOW" }));
        Assert.False(Valid(install with { Severity = "URGENT", Detail = "x" }));
        Assert.False(Valid(install with { Detail = new string('x', 301) }));
        Assert.False(Valid(install with { Detail = "x", FilePath = @"\\server\share\x.sys" }));
        Assert.False(Valid(install with { Detail = "x", FilePath = "relative.sys" }));
        Assert.False(Valid(logon with { Detail = "x" }));
        Assert.False(Valid(logon with { Severity = "CRITICAL", Detail = "x" }));
    }

    [Fact]
    public async Task ServiceInstallAlertsShowTheServiceAndOfferTheFileAndAreRegraded()
    {
        using var database = new SecurityAlertRepositoryTests.TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow;
        var plain = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 77, now.AddMinutes(-5))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [plain], 1, []));
        Assert.Equal("HIGH", Assert.Single((await repository.ReadSnapshotAsync()).Alerts).Severity);

        var described = plain with { Severity = "LOW", Detail = @"MpKslDrv · signed by Microsoft (routine Windows or Defender component) · C:\Windows\System32\drivers\MpKslDrv.sys", FilePath = @"C:\Windows\System32\drivers\MpKslDrv.sys" };
        await repository.IngestAsync(new SecurityEventSnapshot(1, now.AddSeconds(5), [described], 1, []));
        var alert = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);
        Assert.Equal("LOW", alert.Severity);
        Assert.StartsWith("Windows service installed: MpKslDrv · ", alert.Title, StringComparison.Ordinal);
        Assert.True(alert.Title.Length <= 160);
        Assert.Equal(AlertIndicatorKinds.File, alert.IndicatorKind);
        // Regression: the desktop must accept a snapshot containing a graded service install (it rejected the whole
        // snapshot, which blanked Threat Pulse, threat counts and the alert pages).
        var snapshot = await repository.ReadSnapshotAsync();
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Alerts = [alert with { Title = "Something else: x" }] }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Alerts = [alert with { Severity = "URGENT" }] }));
        Assert.Equal(@"C:\Windows\System32\drivers\MpKslDrv.sys", alert.Indicator);
    }
}
