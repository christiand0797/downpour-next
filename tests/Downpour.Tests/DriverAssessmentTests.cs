using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class DriverAssessmentTests
{
    private static DriverInventoryEntry Driver(bool? signed, string? signer = null, bool microsoft = false, bool userWritable = false) =>
        new("gdrv", @"\SystemRoot\System32\drivers\gdrv.sys", !userWritable, userWritable, signed, signer, microsoft);

    private static ThreatMatch Match(string subject, string label, string verdict = "needs-review") =>
        new(DateTimeOffset.UtcNow, ThreatMatchPlaces.Driver, "abc", subject, "loldrivers", "LOLDrivers", label, "HIGH", "T1068", verdict);

    [Fact]
    public void KnownMaliciousHashIsCriticalEvenWhenSigned()
    {
        var verdict = DriverAssessment.Assess(Driver(true, "Some Vendor"), [Match(@"gdrv (C:\Windows\System32\drivers\gdrv.sys)", "malicious driver")]);

        Assert.Equal("CRITICAL", verdict.Severity);
        Assert.Equal("Known malicious driver", verdict.Title);
    }

    [Fact]
    public void ConfirmedVerdictIsCritical()
    {
        var verdict = DriverAssessment.Assess(Driver(true, "Vendor"), [Match("gdrv (x)", "vulnerable driver", ThreatVerdicts.Confirmed)]);

        Assert.Equal("CRITICAL", verdict.Severity);
    }

    [Fact]
    public void VulnerableSignedDriverIsMediumAndNamesTheSigner()
    {
        var verdict = DriverAssessment.Assess(Driver(true, "GIGA-BYTE TECHNOLOGY CO., LTD."), [Match("gdrv (x)", "vulnerable driver")]);

        Assert.Equal("MEDIUM", verdict.Severity);
        Assert.Contains("GIGA-BYTE", verdict.Explanation);
    }

    [Fact]
    public void VulnerableUnsignedDriverIsHigh()
    {
        Assert.Equal("HIGH", DriverAssessment.Assess(Driver(false), [Match("gdrv (x)", "vulnerable driver")]).Severity);
    }

    [Fact]
    public void MatchesForOtherDriversOrPlacesAreIgnored()
    {
        ThreatMatch[] matches =
        [
            Match("gdrv2 (x)", "malicious driver"),
            Match("gdrv (x)", "malicious driver") with { Where = ThreatMatchPlaces.Program },
        ];

        Assert.Equal("OK", DriverAssessment.Assess(Driver(true, "Vendor"), matches).Severity);
    }

    [Fact]
    public void UserWritableLocationIsHigh()
    {
        Assert.Equal("Loaded from a user-writable folder", DriverAssessment.Assess(Driver(true, "Vendor", userWritable: true), []).Title);
    }

    [Theory]
    [InlineData(false, false, "HIGH", "Not validly signed")]
    [InlineData(true, true, "OK", "Windows driver")]
    [InlineData(true, false, "OK", "Signed vendor driver")]
    [InlineData(null, false, "INFO", "Signature not checked")]
    public void SignatureDecidesTheRest(bool? signed, bool microsoft, string severity, string title)
    {
        var verdict = DriverAssessment.Assess(Driver(signed, signed == true ? "Signer" : null, microsoft), []);

        Assert.Equal(severity, verdict.Severity);
        Assert.Equal(title, verdict.Title);
    }

    [Fact]
    public void ProviderVerifiesSignaturesOfLoadedDrivers()
    {
        var snapshot = new DriverInventoryProvider(new FileSignatureChecker()).Capture();
        if (snapshot.Drivers.Count == 0) return;

        // Windows only loads signed kernel drivers, so on a normal PC most must verify and many must be Microsoft's.
        Assert.Contains(snapshot.Drivers, d => d.Signed == true && d.MicrosoftSigned);
        Assert.All(snapshot.Drivers.Where(d => d.Signer is not null), d => Assert.InRange(d.Signer!.Length, 1, 512));
    }
}
