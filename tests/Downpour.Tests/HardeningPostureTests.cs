using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class HardeningPostureTests
{
    private static readonly PostureReadings Empty = new();

    [Fact]
    public void EvaluateReturnsAntivirusThenTheEightV29ChecksInOrder()
    {
        var ids = HardeningPostureEvaluator.Evaluate(Empty).Select(check => check.Id);
        Assert.Equal(["antivirus", "bitlocker", "secure-boot", "tpm", "lsa-ppl", "credential-guard", "vbs-hvci", "smb1", "patch-service"], ids);
    }

    [Theory]
    [InlineData(1, false, PostureStates.Pass, "INFO")]
    [InlineData(0, false, PostureStates.Finding, "HIGH")]
    [InlineData(2, false, PostureStates.Unknown, "INFO")]
    [InlineData(null, true, PostureStates.Unknown, "INFO")]
    public void BitLockerMatchesV29(int? status, bool denied, string state, string severity)
    {
        var check = HardeningPostureEvaluator.BitLocker(Empty with { BitLockerProtectionStatus = status, BitLockerAccessDenied = denied });
        Assert.Equal(state, check.State);
        Assert.Equal(severity, check.Severity);
        if (denied) Assert.Contains("administrator", check.Detail);
    }

    [Theory]
    [InlineData(null, PostureStates.Unknown)]
    [InlineData(0, PostureStates.Finding)]
    [InlineData(1, PostureStates.Pass)]
    public void SecureBootMatchesV29(int? value, string state) =>
        Assert.Equal(state, HardeningPostureEvaluator.SecureBoot(Empty with { SecureBootEnabled = value }).State);

    [Fact]
    public void TpmPresenceComesFromTbsAndReadinessIsOptional()
    {
        Assert.Equal(PostureStates.Unknown, HardeningPostureEvaluator.Tpm(Empty).State);
        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.Tpm(Empty with { TpmPresent = false }).State);

        var presentUnelevated = HardeningPostureEvaluator.Tpm(Empty with { TpmPresent = true, TpmVersion = 2 });
        Assert.Equal(PostureStates.Pass, presentUnelevated.State);
        Assert.Contains("TPM 2.0", presentUnelevated.Detail);
        Assert.Contains("administrator", presentUnelevated.Detail);

        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.Tpm(Empty with { TpmPresent = true, TpmEnabled = true, TpmActivated = false }).State);
        Assert.Equal(PostureStates.Pass, HardeningPostureEvaluator.Tpm(Empty with { TpmPresent = true, TpmEnabled = true, TpmActivated = true }).State);
    }

    [Theory]
    [InlineData(null, PostureStates.Finding)]
    [InlineData(0, PostureStates.Finding)]
    [InlineData(1, PostureStates.Pass)]
    [InlineData(2, PostureStates.Pass)]
    public void LsaProtectionMatchesV29(int? value, string state)
    {
        var check = HardeningPostureEvaluator.LsaProtection(Empty with { RunAsPpl = value });
        Assert.Equal(state, check.State);
        if (state == PostureStates.Finding) Assert.Equal("HIGH", check.Severity);
    }

    [Fact]
    public void CredentialGuardPrefersRunningStateOverRegistry()
    {
        // Windows 11 can run Credential Guard by default with no LsaCfgFlags value; v29 would have flagged this.
        Assert.Equal(PostureStates.Pass, HardeningPostureEvaluator.CredentialGuard(Empty with { DeviceGuardServicesRunning = [1, 2] }).State);
        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.CredentialGuard(Empty with { DeviceGuardServicesRunning = [2], LsaCfgFlags = 1 }).State);

        // Registry fallback reproduces v29.
        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.CredentialGuard(Empty).State);
        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.CredentialGuard(Empty with { LsaCfgFlags = 0 }).State);
        Assert.Equal(PostureStates.Pass, HardeningPostureEvaluator.CredentialGuard(Empty with { LsaCfgFlags = 1 }).State);
    }

    [Fact]
    public void VbsHvciPrefersRunningStateAndFallsBackToV29Registry()
    {
        Assert.Equal(PostureStates.Pass, HardeningPostureEvaluator.VbsHvci(Empty with { DeviceGuardServicesRunning = [2] }).State);
        var vbsOff = HardeningPostureEvaluator.VbsHvci(Empty with { DeviceGuardServicesRunning = [], VbsStatus = 0 });
        Assert.Equal(PostureStates.Finding, vbsOff.State);
        Assert.Contains("off", vbsOff.Detail);

        Assert.Equal(PostureStates.Pass, HardeningPostureEvaluator.VbsHvci(Empty with { HvciRegistryEnabled = 1 }).State);
        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.VbsHvci(Empty).State);
        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.VbsHvci(Empty with { HvciRegistryEnabled = 0 }).State);
        Assert.Equal(PostureStates.Unknown, HardeningPostureEvaluator.VbsHvci(Empty with { VbsRegistryEnabled = 1 }).State);
    }

    [Theory]
    [InlineData(null, PostureStates.Pass)]
    [InlineData(0, PostureStates.Pass)]
    [InlineData(1, PostureStates.Finding)]
    public void Smb1MatchesV29(int? value, string state) =>
        Assert.Equal(state, HardeningPostureEvaluator.Smb1(Empty with { Smb1 = value }).State);

    [Theory]
    [InlineData(null, PostureStates.Unknown)]
    [InlineData(4, PostureStates.Finding)]
    [InlineData(3, PostureStates.Pass)]
    [InlineData(2, PostureStates.Pass)]
    public void PatchServiceMatchesV29(int? value, string state) =>
        Assert.Equal(state, HardeningPostureEvaluator.PatchService(Empty with { WindowsUpdateStart = value }).State);

    [Theory]
    [InlineData(0x061000, true, true)]   // real-time on, definitions current
    [InlineData(0x061010, true, false)]  // on, out of date
    [InlineData(0x060010, false, false)] // off, out of date (Malwarebytes sample from this PC)
    [InlineData(0x061100, false, true)]  // snoozed (Windows Defender sample from this PC)
    public void ProductStateDecoding(int state, bool realTime, bool current) =>
        Assert.Equal((realTime, current), HardeningPostureEvaluator.DecodeProductState(state));

    [Fact]
    public void AntivirusCheckReflectsRealTimeProtection()
    {
        AntivirusProductReading Product(string name, int state) => new(name, state);
        Assert.Equal(PostureStates.Unknown, HardeningPostureEvaluator.Antivirus(Empty).State);
        Assert.Equal(PostureStates.Finding, HardeningPostureEvaluator.Antivirus(Empty with { AntivirusProducts = [] }).State);
        var off = HardeningPostureEvaluator.Antivirus(Empty with { AntivirusProducts = [Product("Malwarebytes", 0x060010), Product("Windows Defender", 0x061100)] });
        Assert.Equal(PostureStates.Finding, off.State);
        Assert.Equal("HIGH", off.Severity);
        Assert.Equal(PostureStates.Pass, HardeningPostureEvaluator.Antivirus(Empty with { AntivirusProducts = [Product("Windows Defender", 0x061000)] }).State);
        var stale = HardeningPostureEvaluator.Antivirus(Empty with { AntivirusProducts = [Product("Windows Defender", 0x061010)] });
        Assert.Equal("MEDIUM", stale.Severity);
    }

    [Fact]
    public void UnreadableValuesNeverProduceFindingsExceptWhereV29TreatsAbsenceAsUnsafe()
    {
        // In v29, an absent RunAsPPL, absent LsaCfgFlags and absent Device Guard keys are findings by design.
        var findings = HardeningPostureEvaluator.Evaluate(Empty)
            .Where(check => check.State == PostureStates.Finding)
            .Select(check => check.Id)
            .ToHashSet();
        Assert.Equal(new HashSet<string> { "lsa-ppl", "credential-guard", "vbs-hvci" }, findings);
    }

    [Fact]
    public void LiveCaptureIsValidAndBounded()
    {
        var snapshot = new HardeningPostureProvider().Capture();
        Assert.True(HardeningPostureClient.IsValid(snapshot));
        Assert.Equal(9, snapshot.Checks.Count);
        // The patch-service and SMB1 checks read world-readable registry values and should never be unknown.
        Assert.NotEqual(PostureStates.Unknown, snapshot.Checks.Single(check => check.Id == "smb1").State);
        Assert.NotEqual(PostureStates.Unknown, snapshot.Checks.Single(check => check.Id == "patch-service").State);
    }

    [Fact]
    public void ClientRejectsUnknownStatesAndOversizedText()
    {
        var good = new HardeningPostureSnapshot(1, DateTimeOffset.UtcNow, false,
            [new PostureCheck("smb1", "SMBv1 server", PostureStates.Pass, "INFO", "T1210", "ok")], []);
        Assert.True(HardeningPostureClient.IsValid(good));
        Assert.False(HardeningPostureClient.IsValid(good with { SchemaVersion = 2 }));
        Assert.False(HardeningPostureClient.IsValid(good with { Checks = [good.Checks[0] with { State = "Fixed" }] }));
        Assert.False(HardeningPostureClient.IsValid(good with { Checks = [good.Checks[0] with { Severity = "SEVERE" }] }));
        Assert.False(HardeningPostureClient.IsValid(good with { Checks = [good.Checks[0] with { Detail = new string('x', 513) }] }));
    }
}
