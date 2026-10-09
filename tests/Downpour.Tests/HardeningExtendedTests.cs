using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class HardeningExtendedTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 0, 0, 0, TimeSpan.Zero);

    private static PostureCheck Check(PostureReadings r, string id) =>
        HardeningPostureEvaluator.EvaluateExtended(r, Now).Single(c => c.Id == id);

    [Fact]
    public void EveryCheckHasGuidanceWithinTheClientLimits()
    {
        var checks = HardeningPostureEvaluator.Evaluate(new PostureReadings())
            .Concat(HardeningPostureEvaluator.EvaluateExtended(new PostureReadings(), Now)).ToArray();
        Assert.InRange(checks.Length, 40, 64);
        Assert.All(checks, check =>
        {
            var guided = HardeningGuidance.Apply(check with { State = PostureStates.Finding, Severity = "MEDIUM" });
            Assert.False(string.IsNullOrWhiteSpace(guided.Category), check.Id);
            Assert.False(string.IsNullOrWhiteSpace(guided.Fix), check.Id);
            Assert.True(guided.Fix!.Length <= 512, check.Id);
            Assert.True(guided.SettingsUri is null || guided.SettingsUri.StartsWith("ms-settings:") || guided.SettingsUri.StartsWith("windowsdefender://"), check.Id);
        });
        Assert.True(HardeningPostureClient.IsValid(new HardeningPostureSnapshot(1, Now, false, checks.Select(HardeningGuidance.Apply).ToArray(), [])));
    }

    [Fact]
    public void PassingChecksCarryNoFix()
    {
        var pass = HardeningGuidance.Apply(new PostureCheck("rdp", "Remote Desktop", PostureStates.Pass, "INFO", "T1021.001", "off"));
        Assert.Null(pass.Fix);
        Assert.Null(pass.SettingsUri);
        Assert.Equal(HardeningGuidance.Network, pass.Category);
    }

    [Fact]
    public void ClientRejectsUnlistedSettingsLinks()
    {
        var check = new PostureCheck("rdp", "Remote Desktop", PostureStates.Finding, "HIGH", "T1021.001", "on", SettingsUri: "https://evil.example/");
        Assert.False(HardeningPostureClient.IsValid(new HardeningPostureSnapshot(1, Now, false, [check], [])));
    }

    [Fact]
    public void CredentialExposuresAreHigh()
    {
        Assert.Equal("HIGH", Check(new PostureReadings { WDigestUseLogonCredential = 1 }, "wdigest").Severity);
        Assert.Equal("HIGH", Check(new PostureReadings { AutoLogonWithStoredPassword = true }, "autologon").Severity);
        Assert.Equal(PostureStates.Pass, Check(new PostureReadings(), "wdigest").State);
    }

    [Theory]
    [InlineData(0, 0, "HIGH")]
    [InlineData(0, 1, "MEDIUM")]
    [InlineData(1, 1, "INFO")]
    public void RemoteDesktopGradesNla(int deny, int nla, string severity) =>
        Assert.Equal(severity, Check(new PostureReadings { DenyTsConnections = deny, RdpUserAuthentication = nla }, "rdp").Severity);

    [Fact]
    public void UacOffOrSilentElevationIsHigh()
    {
        Assert.Equal("HIGH", Check(new PostureReadings { EnableLua = 0 }, "uac").Severity);
        Assert.Equal("HIGH", Check(new PostureReadings { EnableLua = 1, ConsentPromptBehaviorAdmin = 0 }, "uac").Severity);
        Assert.Equal(PostureStates.Pass, Check(new PostureReadings { EnableLua = 1, ConsentPromptBehaviorAdmin = 5, PromptOnSecureDesktop = 1 }, "uac").State);
    }

    [Fact]
    public void FirewallOffOnPublicIsHigh()
    {
        var r = new PostureReadings { FirewallProfiles = new Dictionary<string, int?> { ["Domain"] = 1, ["Private"] = 1, ["Public"] = 0 } };
        Assert.Equal("HIGH", Check(r, "firewall").Severity);
    }

    [Fact]
    public void DefenderChecksStepAsideForAnotherAntivirus()
    {
        var r = new PostureReadings { Defender = new DefenderReading(false, null, null, null, 0, 2, 0, 0, 0, 0) };
        Assert.All(new[] { "defender-cloud", "defender-pua", "defender-tamper", "controlled-folders" }, id => Assert.Equal(PostureStates.Pass, Check(r, id).State));
        var off = new PostureReadings { Defender = new DefenderReading(true, true, false, 9, 0, 2, 0, 0, 0, 0) };
        Assert.Equal("HIGH", Check(off, "defender-tamper").Severity);
        Assert.Equal("HIGH", Check(off, "defender-signatures").Severity);
        Assert.Equal("MEDIUM", Check(off, "defender-cloud").Severity);
    }

    [Theory]
    [InlineData(19045, "CRITICAL")]   // Windows 10 22H2 ended 2025-10-14
    [InlineData(22631, "CRITICAL")]   // Windows 11 23H2 ended 2025-11-11
    [InlineData(26100, "MEDIUM")]     // Windows 11 24H2 ends 2026-10-13, five days after Now
    [InlineData(26200, "INFO")]       // Windows 11 25H2 supported
    [InlineData(27975, "HIGH")]       // Insider build no longer enrolled
    [InlineData(17763, "CRITICAL")]   // old Windows 10
    public void OsSupportFollowsTheLifecycle(int build, string severity) =>
        Assert.Equal(severity, Check(new PostureReadings { OsBuild = build }, "os-support").Severity);

    [Theory]
    [InlineData(10, "INFO")]
    [InlineData(40, "MEDIUM")]
    [InlineData(90, "HIGH")]
    public void UpdateAgeGrades(int days, string severity) =>
        Assert.Equal(severity, Check(new PostureReadings { LastUpdateInstalled = Now.AddDays(-days) }, "update-age").Severity);

    [Fact]
    public void EnrolledInsiderBuildPasses() =>
        Assert.Equal(PostureStates.Pass, Check(new PostureReadings { OsBuild = 27975, InsiderBranch = "CanaryChannel" }, "os-support").State);

    [Fact]
    public void PointAndPrintWithoutElevationIsPrintNightmare()
    {
        Assert.Equal("HIGH", Check(new PostureReadings { PointAndPrintNoWarningNoElevation = 1, SpoolerStart = 2 }, "printnightmare").Severity);
        Assert.Equal(PostureStates.Pass, Check(new PostureReadings { PointAndPrintNoWarningNoElevation = 1, SpoolerStart = 4 }, "printnightmare").State);
    }

    [Theory]
    [InlineData("10/1/2026", 2026, 10, 1)]
    [InlineData("20260915", 2026, 9, 15)]
    public void InstalledOnFormatsParse(string value, int year, int month, int day)
    {
        var date = HardeningPostureProvider.ParseInstalledOn(value);
        Assert.Equal(new DateTime(year, month, day), date!.Value.UtcDateTime.Date);
    }

    [Fact]
    public void InstalledOnRejectsJunk()
    {
        Assert.Null(HardeningPostureProvider.ParseInstalledOn(""));
        Assert.Null(HardeningPostureProvider.ParseInstalledOn("not a date"));
    }
}
