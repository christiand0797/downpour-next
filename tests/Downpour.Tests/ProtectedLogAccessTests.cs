using Downpour.Service;

namespace Downpour.Tests;

public sealed class ProtectedLogAccessTests
{
    [Theory]
    [InlineData("Security")]
    [InlineData("Microsoft-Windows-Sysmon/Operational")]
    public void AccessWarningIsBoundedNamesTheLogAndCarriesTheFixMarker(string log)
    {
        var warning = SecurityEventProvider.AccessDeniedWarning(log);

        Assert.InRange(warning.Length, 1, 512);
        Assert.Contains(log, warning);
        Assert.Contains(SecurityEventProvider.EventLogReadersMarker, warning);
        Assert.DoesNotContain(warning, char.IsControl);
    }

    [Fact]
    public void CanReadIsTrueForAnOpenLogAndNeverThrowsForMissingOnes()
    {
        Assert.True(SecurityEventProvider.CanRead("Application"));
        _ = SecurityEventProvider.CanRead("Downpour-No-Such-Log/Operational");
    }

    [Fact]
    public void CaptureReportsProtectedLogsWithTheFixInsteadOfAGenericDenial()
    {
        var snapshot = new SecurityEventProvider().Capture();

        Assert.DoesNotContain(snapshot.Warnings, w => w.StartsWith("Permission denied", StringComparison.Ordinal));
        if (!SecurityEventProvider.CanRead("Security"))
            Assert.Contains(SecurityEventProvider.AccessDeniedWarning("Security"), snapshot.Warnings);
    }
}
