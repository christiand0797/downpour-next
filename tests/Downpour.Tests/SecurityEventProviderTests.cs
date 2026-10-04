using Downpour.Service;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class SecurityEventProviderTests
{
    [Fact]
    public void WatchedEventIdsCoverTheV29EventWatchSet()
    {
        Assert.Equal(new[] { 21, 22, 24, 25, 104, 1102, 1116, 1117, 1149, 4104, 4625, 4663, 4672, 4673, 4688, 4697, 4698, 4699,
            4720, 4726, 4728, 4732, 4738, 4740, 4776, 5001, 5003, 5004, 5007, 5010, 5012, 5152, 5156, 5157, 7045 },
            SecurityEventProvider.WatchedEventIds);
        Assert.Equal(35, SecurityEventCatalog.WatchedEvents.Count);
    }

    [Theory]
    [InlineData("System", 7045, "HIGH", "T1543.003", "Windows service installed")]
    [InlineData("Security", 1102, "CRITICAL", "T1070.001", "Security audit log cleared")]
    [InlineData("Security", 4698, "HIGH", "T1053.005", "Scheduled task created")]
    [InlineData("Microsoft-Windows-PowerShell/Operational", 4104, "LOW", "T1059.001", "PowerShell script block recorded")]
    public void AllowedEventGetsStableMinimizedClassification(string log, int eventId, string severity, string technique, string summary)
    {
        var result = SecurityEventProvider.CreateObservation(log, "Provider\r\nName", eventId, 12, DateTimeOffset.UtcNow);

        Assert.NotNull(result);
        Assert.Equal(severity, result.Severity);
        Assert.Equal(technique, result.Technique);
        Assert.Equal(summary, result.Summary);
        Assert.Equal("ProviderName", result.Provider);
    }

    [Theory]
    [InlineData("Security", 7045)]
    [InlineData("System", 1102)]
    [InlineData("Application", 4625)]
    [InlineData("Security", 1)]
    public void EventOutsideFixedLogAndIdAllowListIsRejected(string log, int eventId)
    {
        Assert.Null(SecurityEventProvider.CreateObservation(log, "Provider", eventId, 1, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ClientAcceptsCanonicalBoundedEventSnapshot()
    {
        var now = DateTimeOffset.UtcNow;
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 123, now);
        var snapshot = new SecurityEventSnapshot(1, now, [observation!], 3, []);

        Assert.True(SecurityEventClient.IsValidSnapshot(snapshot));
    }

    [Fact]
    public void ClientRejectsUnknownEventAndUnboundedProviderMetadata()
    {
        var now = DateTimeOffset.UtcNow;
        var unknown = new SecurityEventSnapshot(1, now,
            [new SecurityEventObservation("System", "Trusted-looking", 1, 1, now, "LOW", "T1059", "Process creation recorded")], 3, []);
        var oversized = new SecurityEventSnapshot(1, now,
            [new SecurityEventObservation("System", new string('P', 129), 7045, 1, now, "HIGH", "T1543.003", "Windows service installed")], 3, []);

        Assert.False(SecurityEventClient.IsValidSnapshot(unknown));
        Assert.False(SecurityEventClient.IsValidSnapshot(oversized));
    }

    [Fact]
    public void ClientRejectsDuplicateWindowsEventRecord()
    {
        var now = DateTimeOffset.UtcNow;
        var observation = SecurityEventProvider.CreateObservation("System", "Provider", 7045, 7, now)!;
        var snapshot = new SecurityEventSnapshot(1, now, [observation, observation], 3, []);

        Assert.False(SecurityEventClient.IsValidSnapshot(snapshot));
    }

    [Fact]
    public void FailedLogonBurstIsRaisedOnlyAtTheTenInFiveMinuteThreshold()
    {
        var now = DateTimeOffset.UtcNow;

        Assert.Null(SecurityEventProvider.CreateFailedLogonBurst(9, 90, now));
        var burst = SecurityEventProvider.CreateFailedLogonBurst(10, 100, now);

        Assert.NotNull(burst);
        Assert.Equal("HIGH", burst.Severity);
        Assert.Equal(10, burst.Occurrences);
        Assert.Equal("Brute-force logon burst detected", burst.Summary);
        Assert.True(SecurityEventClient.IsValidSnapshot(new SecurityEventSnapshot(1, now, [burst], 7, [])));
    }

    [Fact]
    public async Task SecurityEventPipeReturnsTheLatestBoundedSnapshot()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var pipeName = $"Downpour.EventTest.{Guid.NewGuid():N}";
        var store = new SecurityEventSnapshotStore();
        var now = DateTimeOffset.UtcNow;
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 42, now)!;
        store.Publish(new SecurityEventSnapshot(1, now, [observation], 7, []));
        using var service = new SecurityEventPipeWorker(store, NullLogger<SecurityEventPipeWorker>.Instance, pipeName);
        var client = new SecurityEventClient(pipeName);
        await service.StartAsync(shutdown.Token);

        try
        {
            SecurityEventSnapshot? snapshot = null;
            for (var attempt = 0; attempt < 10 && snapshot is null; attempt++)
            {
                snapshot = await client.TryGetSnapshotAsync(shutdown.Token);
                if (snapshot is null) await Task.Delay(100, shutdown.Token);
            }

            Assert.NotNull(snapshot);
            Assert.Equal(1, snapshot.SchemaVersion);
            Assert.Single(snapshot.Events);
            Assert.Equal(7045, snapshot.Events[0].EventId);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }
}
