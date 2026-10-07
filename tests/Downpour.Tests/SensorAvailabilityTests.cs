using Downpour.Service;

namespace Downpour.Tests;

public sealed class SensorAvailabilityTests
{
    [Theory]
    [InlineData(unchecked((int)0x80070103), "no antimalware provider")]
    [InlineData(unchecked((int)0x80070005), "denied")]
    [InlineData(unchecked((int)0x8007007E), "amsi.dll")]
    [InlineData(unchecked((int)0x80004005), "0x80004005")]
    public void AmsiFailuresAreExplainedInPlainLanguage(int hresult, string expected) =>
        Assert.Contains(expected, AmsiIntegration.DescribeInitializeFailure(hresult));

    [Fact]
    public void SysmonCaptureReportsMissingInstallOnceAndNeverThrows()
    {
        var snapshot = new SysmonProvider().Capture();
        if (SysmonProvider.IsSysmonLogPresent())
        {
            Assert.DoesNotContain(snapshot.Warnings, warning => warning.Contains("not installed"));
            return;
        }
        Assert.Empty(snapshot.Events);
        var warning = Assert.Single(snapshot.Warnings);
        Assert.Contains("not installed", warning);
    }

    [Fact]
    public void SysmonSubscriptionDoesNotReportReadErrorsWhenSysmonIsAbsent()
    {
        if (SysmonProvider.IsSysmonLogPresent()) return;
        var warnings = new List<string>();
        using var subscription = new SysmonProvider().SubscribePush(_ => { }, warnings.Add, out var active);
        Assert.Equal(0, active);
        var warning = Assert.Single(warnings);
        Assert.Contains("not installed", warning);
    }
}
