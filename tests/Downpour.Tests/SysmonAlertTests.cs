using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class SysmonAlertTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "downpour-sysmon-" + Guid.NewGuid().ToString("N"));
    private SecurityAlertRepository _repository = null!;
    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        _repository = new(Path.Combine(_directory, "alerts.db"));
        await _repository.InitializeAsync();
    }
    public Task DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, true);
        return Task.CompletedTask;
    }
    private static SysmonObservation Event(int id, long record = 42, DateTimeOffset? time = null) =>
        SysmonProvider.CreateObservation(SysmonCatalog.LogName, SysmonCatalog.ProviderName, id, record, time ?? DateTimeOffset.UtcNow)!;

    [Theory]
    [InlineData(8, "MEDIUM")]
    [InlineData(9, "MEDIUM")]
    [InlineData(25, "HIGH")]
    public async Task ReviewEventsReachPersistentAlertsAndPassDesktopValidation(int id, string severity)
    {
        var source = SysmonAlertBatch.Create([Event(id)], DateTimeOffset.UtcNow);
        Assert.True(SecurityEventClient.IsValidSnapshot(source));
        await _repository.IngestAsync(source);
        await _repository.IngestAsync(source);
        var result = await _repository.ReadSnapshotAsync();
        var alert = Assert.Single(result.Alerts);
        Assert.Equal(severity, alert.Severity);
        Assert.Contains("review required", alert.Title);
        Assert.True(SecurityAlertClient.IsValidSnapshot(result));
        var request = new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "Suppressed");
        Assert.True((await _repository.ChangeStateAsync(request)).Accepted);
        await _repository.IngestAsync(source);
        Assert.Equal("Suppressed", Assert.Single((await _repository.ReadSnapshotAsync()).Alerts).State);
    }

    [Theory]
    [InlineData(1)] [InlineData(3)] [InlineData(10)] [InlineData(16)] [InlineData(22)] [InlineData(255)]
    public void RoutineActivityAndSensorErrorsAreNotPromotedToThreats(int id) =>
        Assert.Empty(SysmonAlertBatch.Create([Event(id)], DateTimeOffset.UtcNow).Events);

    [Fact]
    public async Task LogRecordReuseAfterClearDoesNotOverwriteAnEarlierAlert()
    {
        var first = Event(25, time: DateTimeOffset.UtcNow.AddMinutes(-1));
        await _repository.IngestAsync(SysmonAlertBatch.Create([first], DateTimeOffset.UtcNow));
        await _repository.IngestAsync(SysmonAlertBatch.Create([Event(25)], DateTimeOffset.UtcNow));
        Assert.Equal(2, (await _repository.ReadSnapshotAsync()).TotalCount);
    }

    [Fact]
    public void UnknownProvidersMissingTimesAndStaleRecordsAreDiscarded()
    {
        var now = DateTimeOffset.UtcNow;
        var original = Event(25);
        Assert.Empty(SysmonAlertBatch.Create([
            original with { Provider = "Spoofed" }, original with { CreatedAtUtc = null },
            original with { CreatedAtUtc = now.AddDays(-2) }, original with { RecordId = null }], now).Events);
        Assert.Null(SysmonProvider.CreateObservation(SysmonCatalog.LogName, "Spoofed", 25, 1, now));
    }

    [Theory]
    [InlineData(4, "Sysmon service state change")]
    [InlineData(13, "Registry value set")]
    [InlineData(16, "Sysmon configuration change")]
    [InlineData(17, "Named pipe creation")]
    [InlineData(21, "WMI consumer to filter binding")]
    [InlineData(22, "DNS query")]
    [InlineData(25, "Process image tampering")]
    [InlineData(255, "Sysmon internal error")]
    public void EventLabelsMatchTheDocumentedWindowsSchema(int id, string expected)
    {
        Assert.True(SysmonCatalog.TryGetRule(SysmonCatalog.LogName, id, out var rule));
        Assert.Equal(expected, rule.Summary);
    }

    [Fact]
    public void ClipboardActivityAndUndocumentedIdsAreOutsideTheCollectionCatalog()
    {
        Assert.DoesNotContain(24, SysmonCatalog.WatchedEventIds);
        Assert.False(SysmonCatalog.TryGetRule(SysmonCatalog.LogName, 256, out _));
        Assert.Null(SysmonProvider.CreateObservation(SysmonCatalog.LogName, SysmonCatalog.ProviderName, 24, 1, DateTimeOffset.UtcNow));
    }
}
