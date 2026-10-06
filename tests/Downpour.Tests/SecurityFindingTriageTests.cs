using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class SecurityFindingTriageTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"downpour-triage-{Guid.NewGuid():N}");
    private SecurityAlertRepository _repository = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        _repository = new SecurityAlertRepository(Path.Combine(_directory, "alerts.db"));
        await _repository.InitializeAsync();
    }

    public Task DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
        return Task.CompletedTask;
    }

    private static SecurityFindingObservation Finding(string indicator, string severity = "MEDIUM", string source = SecurityFindingCatalog.Persistence) =>
        SecurityFindingMapper.Create(source, "Scheduled task", severity, "T1053.005", $"Scheduled task new: {indicator}", indicator);

    private async Task<SecurityAlert> Single(string indicator)
    {
        var snapshot = await _repository.ReadSnapshotAsync();
        return snapshot.Alerts.Single(alert => alert.Title.EndsWith(indicator, StringComparison.Ordinal));
    }

    private Task<AlertStateChangeResponse> Change(SecurityAlert alert, string next) =>
        _repository.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, alert.State, next));

    [Fact]
    public async Task FindingsAreDeduplicatedAndPassClientValidation()
    {
        var now = DateTimeOffset.UtcNow;
        await _repository.IngestFindingsAsync([Finding(@"\Evil"), Finding(@"\Other", "HIGH", SecurityFindingCatalog.Firewall)], now);
        await _repository.IngestFindingsAsync([Finding(@"\Evil")], now.AddSeconds(1));

        var snapshot = await _repository.ReadSnapshotAsync();
        Assert.Equal(2, snapshot.TotalCount);
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
        var evil = snapshot.Alerts.Single(alert => alert.Title.EndsWith(@"\Evil"));
        Assert.Equal(SecurityFindingCatalog.Persistence, evil.LogName);
        Assert.True(SecurityFindingCatalog.IsValidIdentity(evil.Provider));
        Assert.Equal(0, evil.EventId);
        Assert.False(SecurityFindingCatalog.IsThreat(evil));
        Assert.True(SecurityFindingCatalog.IsThreat(snapshot.Alerts.Single(alert => alert.Title.EndsWith(@"\Other"))));
    }

    [Fact]
    public async Task VerifyMovesAnItemToThreatsAndUnverifyMovesItBack()
    {
        await _repository.IngestFindingsAsync([Finding(@"\Pending")], DateTimeOffset.UtcNow);
        var alert = await Single(@"\Pending");

        var verified = await Change(alert, "Verify");
        Assert.True(verified.Accepted);
        Assert.Equal("verified", verified.ResultCode);
        alert = await Single(@"\Pending");
        Assert.True(alert.IsVerified);
        Assert.True(SecurityFindingCatalog.IsThreat(alert));

        var unverified = await Change(alert, "Unverify");
        Assert.Equal("unverified", unverified.ResultCode);
        Assert.False((await Single(@"\Pending")).IsVerified);
    }

    [Fact]
    public async Task VerifyIsReplaySafeAndDeniedForDismissedItems()
    {
        await _repository.IngestFindingsAsync([Finding(@"\Replay")], DateTimeOffset.UtcNow);
        var alert = await Single(@"\Replay");
        var request = new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, alert.State, "Verify");
        Assert.Equal("verified", (await _repository.ChangeStateAsync(request)).ResultCode);
        var replay = await _repository.ChangeStateAsync(request);
        Assert.True(replay.Accepted);
        Assert.Equal("replayed", replay.ResultCode);

        await _repository.IngestFindingsAsync([Finding(@"\Dismissed")], DateTimeOffset.UtcNow);
        var dismissed = await Single(@"\Dismissed");
        Assert.Equal("updated", (await Change(dismissed, "Suppressed")).ResultCode);
        dismissed = await Single(@"\Dismissed");
        var denied = await Change(dismissed, "Verify");
        Assert.False(denied.Accepted);
        Assert.Equal("transition-denied", denied.ResultCode);
    }

    [Fact]
    public async Task FalsePositiveSuppressionIsPerFindingNotPerSource()
    {
        var now = DateTimeOffset.UtcNow;
        await _repository.IngestFindingsAsync([Finding(@"\Noisy"), Finding(@"\Unrelated")], now);
        for (var i = 0; i < SecurityAlertRepository.FalsePositiveConfirmationThreshold; i++)
        {
            var noisy = await Single(@"\Noisy");
            if (noisy.State == "Suppressed") break;
            Assert.True((await Change(noisy, "FalsePositive")).Accepted);
        }

        Assert.Equal("Suppressed", (await Single(@"\Noisy")).State);
        Assert.Equal("Open", (await Single(@"\Unrelated")).State);

        // A later detection of the same finding stays suppressed.
        await _repository.IngestFindingsAsync([Finding(@"\Noisy")], now.AddMinutes(10));
        Assert.Equal("Suppressed", (await Single(@"\Noisy")).State);
    }

    [Fact]
    public async Task IngestRejectsUnknownSourcesAndOversizedFields()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() => _repository.IngestFindingsAsync(
            [new SecurityFindingObservation("Elsewhere", "c", "HIGH", "T1", "s", "i")], DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<InvalidDataException>(() => _repository.IngestFindingsAsync(
            [new SecurityFindingObservation(SecurityFindingCatalog.Firewall, "c", "INFO", "T1", "s", "i")], DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<InvalidDataException>(() => _repository.IngestFindingsAsync(
            [new SecurityFindingObservation(SecurityFindingCatalog.Firewall, "c", "HIGH", "T1", new string('x', 161), "i")], DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ClientValidatesVerifyRequestsAndResponses()
    {
        var id = new string('a', 64);
        Assert.True(SecurityAlertClient.IsValidRequest(new(1, Guid.NewGuid(), id, "Open", "Verify")));
        Assert.True(SecurityAlertClient.IsValidRequest(new(1, Guid.NewGuid(), id, "Suppressed", "Unverify")));
        Assert.False(SecurityAlertClient.IsValidRequest(new(1, Guid.NewGuid(), id, "Suppressed", "Verify")));
        var request = Guid.NewGuid();
        Assert.True(SecurityAlertClient.IsValidResponse(new(1, request, true, "verified"), request));
        Assert.False(SecurityAlertClient.IsValidResponse(new(1, request, false, "verified"), request));
    }

    [Fact]
    public void MapperKeepsOnlyRealFindingsAndBoundsText()
    {
        var hardening = new HardeningPostureSnapshot(1, DateTimeOffset.UtcNow, false,
        [
            new PostureCheck("smb1", "SMBv1 server", PostureStates.Finding, "HIGH", "T1210", "SMBv1 is enabled"),
            new PostureCheck("tpm", "TPM", PostureStates.Pass, "INFO", "", "present"),
            new PostureCheck("bitlocker", "BitLocker", PostureStates.Unknown, "INFO", "T1490", "needs admin"),
        ], []);
        var mapped = Assert.Single(SecurityFindingMapper.FromHardening(hardening));
        Assert.Equal(SecurityFindingCatalog.Hardening, mapped.Source);
        Assert.Equal("smb1", mapped.Indicator);

        var longSummary = SecurityFindingMapper.Create(SecurityFindingCatalog.Firewall, "Firewall", "HIGH", "", new string('y', 400), "i");
        Assert.True(longSummary.Summary.Length <= SecurityFindingMapper.MaximumTitle);
        Assert.Equal("Posture", longSummary.Technique);
    }

    [Fact]
    public void FindingIdentityIgnoresSummaryWordingButNotIndicator()
    {
        var a = SecurityFindingMapper.Create(SecurityFindingCatalog.Persistence, "Scheduled task", "HIGH", "T1053.005", "Scheduled task new: X", @"\X");
        var b = a with { Summary = "Scheduled task modified: X" };
        var c = a with { Indicator = @"\Y" };
        Assert.Equal(SecurityFindingMapper.Identity(a), SecurityFindingMapper.Identity(b));
        Assert.NotEqual(SecurityFindingMapper.Identity(a), SecurityFindingMapper.Identity(c));
    }
}
