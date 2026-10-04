using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class SecurityAlertRepositoryTests
{
    [Fact]
    public async Task EventRecordsBecomeStableDeduplicatedAndDurableAlerts()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var wallClock = DateTimeOffset.UtcNow;
        var now = DateTimeOffset.FromUnixTimeSeconds(wallClock.ToUnixTimeSeconds() / 300 * 300).AddSeconds(30);
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 42, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [observation], 7, []));
        var initial = await repository.ReadSnapshotAsync();

        Assert.Equal(1, initial.TotalCount);
        var alert = Assert.Single(initial.Alerts);
        Assert.True(SecurityAlertRepository.IsValidAlertId(alert.AlertId));
        Assert.Equal("Open", alert.State);
        Assert.Equal(1, alert.Occurrences);

        var reopened = new SecurityAlertRepository(database.Path);
        await reopened.InitializeAsync();
        var later = now.AddSeconds(15);
        await reopened.IngestAsync(new SecurityEventSnapshot(1, later, [observation], 7, []));
        var durable = await reopened.ReadSnapshotAsync();

        var persisted = Assert.Single(durable.Alerts);
        Assert.Equal(alert.AlertId, persisted.AlertId);
        Assert.Equal("Open", persisted.State);
        Assert.Equal(1, persisted.Occurrences);
        Assert.True(persisted.LastSeenUtc > persisted.FirstSeenUtc);
    }

    [Fact]
    public async Task AcknowledgeSuppressAndReopenAreAuditedExpectedStateTransitions()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow;
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 9, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [observation], 7, []));
        var alert = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);

        var ackRequest = new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "Acknowledged");
        Assert.Equal("updated", (await repository.ChangeStateAsync(ackRequest)).ResultCode);
        Assert.Equal("replayed", (await repository.ChangeStateAsync(ackRequest)).ResultCode);
        Assert.Equal("request-id-conflict", (await repository.ChangeStateAsync(ackRequest with { State = "Suppressed" })).ResultCode);
        Assert.Equal("state-conflict", (await repository.ChangeStateAsync(
            new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "Suppressed"))).ResultCode);

        var suppress = new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Acknowledged", "Suppressed");
        Assert.Equal("updated", (await repository.ChangeStateAsync(suppress)).ResultCode);
        await repository.IngestAsync(new SecurityEventSnapshot(1, now.AddSeconds(15), [observation], 7, []));
        Assert.Equal("Suppressed", Assert.Single((await repository.ReadSnapshotAsync()).Alerts).State);

        var reopen = new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Suppressed", "Open");
        Assert.Equal("updated", (await repository.ChangeStateAsync(reopen)).ResultCode);
        Assert.Equal("Open", Assert.Single((await repository.ReadSnapshotAsync()).Alerts).State);
    }

    [Fact]
    public async Task FailedLogonBurstDeduplicatesWithinFiveMinuteWindowAndKeepsMaximumCount()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var wallClock = DateTimeOffset.UtcNow;
        var now = DateTimeOffset.FromUnixTimeSeconds(wallClock.ToUnixTimeSeconds() / 300 * 300).AddSeconds(30);
        var first = SecurityEventProvider.CreateFailedLogonBurst(10, 100, now)!;
        var second = SecurityEventProvider.CreateFailedLogonBurst(24, 114, now.AddSeconds(20))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [first], 7, []));
        await repository.IngestAsync(new SecurityEventSnapshot(1, now.AddSeconds(20), [second], 7, []));

        var burst = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);
        Assert.Equal("T1110", burst.Technique);
        Assert.Equal(24, burst.Occurrences);
        Assert.Equal(114L, burst.RecordId);
    }

    [Fact]
    public async Task AlertSnapshotAndTriagePipesExchangeBoundedLocalData()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow;
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 17, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [observation], 7, []));
        var snapshots = new SecurityAlertSnapshotStore();
        snapshots.Publish(await repository.ReadSnapshotAsync());
        var suffix = Guid.NewGuid().ToString("N");
        using var snapshotWorker = new SecurityAlertPipeWorker(snapshots, NullLogger<SecurityAlertPipeWorker>.Instance, $"Downpour.Alerts.{suffix}");
        using var controlWorker = new SecurityAlertControlPipeWorker(repository, snapshots,
            NullLogger<SecurityAlertControlPipeWorker>.Instance, $"Downpour.Alerts.{suffix}.Control");
        var client = new SecurityAlertClient($"Downpour.Alerts.{suffix}");
        await snapshotWorker.StartAsync(CancellationToken.None);
        await controlWorker.StartAsync(CancellationToken.None);

        try
        {
            SecurityAlertSnapshot? snapshot = null;
            for (var attempt = 0; attempt < 10 && snapshot is null; attempt++)
            {
                snapshot = await client.TryGetSnapshotAsync();
                if (snapshot is null) await Task.Delay(100);
            }
            Assert.NotNull(snapshot);
            var alert = Assert.Single(snapshot.Alerts);
            var request = new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "Acknowledged");
            var response = await client.ChangeStateAsync(request);
            Assert.NotNull(response);
            Assert.True(response.Accepted);
            Assert.Equal("updated", response.ResultCode);
            var changed = await repository.ReadSnapshotAsync();
            Assert.Equal("Acknowledged", Assert.Single(changed.Alerts).State);
            Assert.True(SecurityAlertClient.IsValidSnapshot(changed));
        }
        finally
        {
            await controlWorker.StopAsync(CancellationToken.None);
            await snapshotWorker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public void ClientRejectsUntrustedStateAndMalformedIds()
    {
        Assert.True(SecurityAlertClient.IsValidRequest(new AlertStateChangeRequest(1, Guid.NewGuid(), new string('a', 64), "Open", "Acknowledged")));
        Assert.False(SecurityAlertClient.IsValidRequest(new AlertStateChangeRequest(1, Guid.NewGuid(), new string('A', 64), "Open", "Acknowledged")));
        Assert.False(SecurityAlertClient.IsValidRequest(new AlertStateChangeRequest(1, Guid.NewGuid(), new string('a', 64), "Suppressed", "Acknowledged")));
        Assert.False(SecurityAlertClient.IsValidResponse(new AlertStateChangeResponse(1, Guid.NewGuid(), true, "updated"), Guid.NewGuid()));
    }

    [Fact]
    public void ControlPipeRejectsDuplicateUnknownAndOversizedRequestProperties()
    {
        var valid = "{\"schemaVersion\":1,\"requestId\":\"11111111-1111-1111-1111-111111111111\",\"alertId\":\"" + new string('a', 64) + "\",\"expectedState\":\"Open\",\"state\":\"Acknowledged\"}";
        Assert.NotNull(SecurityAlertControlPipeWorker.ParseStrictRequest(System.Text.Encoding.UTF8.GetBytes(valid)));
        Assert.Null(SecurityAlertControlPipeWorker.ParseStrictRequest(System.Text.Encoding.UTF8.GetBytes(valid.Replace("\"state\":\"Acknowledged\"", "\"state\":\"Acknowledged\",\"state\":\"Suppressed\""))));
        Assert.Null(SecurityAlertControlPipeWorker.ParseStrictRequest(System.Text.Encoding.UTF8.GetBytes(valid[..^1] + ",\"extra\":true}")));
        Assert.Null(SecurityAlertControlPipeWorker.ParseStrictRequest(new byte[1025]));
    }

    private sealed class TemporaryAlertDatabase : IDisposable
    {
        private readonly string _root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"DownpourAlerts-{Guid.NewGuid():N}");
        public string Path => System.IO.Path.Combine(_root, "alerts.db");

        public TemporaryAlertDatabase()
        {
            SecureJournalDirectory.Ensure(_root);
        }

        public void Dispose()
        {
            if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
        }
    }
}
