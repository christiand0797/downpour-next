using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class SecurityAlertRepositoryTests
{
    [Fact]
    public async Task NoisyInformationalEventsRollUpPerHourAndCountEachRecordOnce()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var past = DateTimeOffset.UtcNow.AddHours(-3);
        var hour = new DateTimeOffset(past.Year, past.Month, past.Day, past.Hour, 0, 0, TimeSpan.Zero);
        var events = Enumerable.Range(1, 3)
            .Select(i => SecurityEventProvider.CreateObservation("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, 100 + i, hour.AddMinutes(i))!)
            .ToArray();
        foreach (var e in events) await repository.IngestAsync(new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, [e], 1, []));
        // Polling reads the same records again; they must not be counted twice.
        await repository.IngestAsync(new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, events, 3, []));

        var alert = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);
        Assert.Equal(3, alert.Occurrences);

        var nextHour = SecurityEventProvider.CreateObservation("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, 200, hour.AddHours(1).AddMinutes(1))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, [nextHour], 1, []));
        Assert.Equal(2, (await repository.ReadSnapshotAsync()).Alerts.Count);
    }

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
    public async Task FalsePositiveRuleRequiresThreeConfirmationsSuppressesMatchesAndCanBeRearmed()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow.AddMinutes(-4);
        var firstObservation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 51, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [firstObservation], 7, []));
        var firstAlert = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);

        var firstConfirmation = new AlertStateChangeRequest(1, Guid.NewGuid(), firstAlert.AlertId, "Open", "FalsePositive");
        Assert.Equal("confirmed-1", (await repository.ChangeStateAsync(firstConfirmation)).ResultCode);
        Assert.Equal("replayed", (await repository.ChangeStateAsync(firstConfirmation)).ResultCode);
        Assert.Equal("confirmed-2", (await repository.ChangeStateAsync(firstConfirmation with { RequestId = Guid.NewGuid() })).ResultCode);
        Assert.Equal("fingerprint-suppressed", (await repository.ChangeStateAsync(firstConfirmation with { RequestId = Guid.NewGuid() })).ResultCode);

        var suppressed = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);
        Assert.Equal("Suppressed", suppressed.State);
        var laterObservation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 52, now.AddMinutes(1))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now.AddMinutes(1), [laterObservation], 7, []));
        Assert.Contains((await repository.ReadSnapshotAsync()).Alerts, alert => alert.AlertId != firstAlert.AlertId && alert.State == "Suppressed");

        var rearm = new AlertStateChangeRequest(1, Guid.NewGuid(), firstAlert.AlertId, "Suppressed", "RearmFalsePositive");
        Assert.Equal("rearmed", (await repository.ChangeStateAsync(rearm)).ResultCode);
        Assert.All((await repository.ReadSnapshotAsync()).Alerts, alert => Assert.Equal("Open", alert.State));
        var nextObservation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 53, now.AddMinutes(2))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now.AddMinutes(2), [nextObservation], 7, []));
        Assert.Contains((await repository.ReadSnapshotAsync()).Alerts, alert => alert.AlertId != firstAlert.AlertId && alert.State == "Open");
    }

    [Fact]
    public async Task SuppressionRecordsExpiryAndCountsTheMatchesItHides()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow.AddMinutes(-4);
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 71, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [observation], 7, []));
        var alert = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);
        for (var confirmation = 0; confirmation < SecurityAlertRepository.FalsePositiveConfirmationThreshold; confirmation++)
            await repository.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "FalsePositive"));

        var blocked = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 72, now.AddMinutes(1))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now.AddMinutes(1), [blocked], 7, []));
        var snapshot = await repository.ReadSnapshotAsync();
        Assert.Equal("Suppressed", snapshot.Alerts.Single(row => row.RecordId == 72).State);
        Assert.Contains(snapshot.Warnings, warning => warning.Contains("active") && warning.Contains("expire"));

        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={database.Path};Pooling=False");
        await connection.OpenAsync();
        await using var query = connection.CreateCommand();
        query.CommandText = "SELECT expires_at_utc,matches_since_grant,suppressed FROM alert_fp_rules;";
        await using var reader = await query.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.False(reader.IsDBNull(0));
        Assert.True(DateTimeOffset.Parse(reader.GetString(0)) > DateTimeOffset.UtcNow.AddDays(80));
        Assert.True(reader.GetInt32(1) >= 1, "The suppression must record the matches it hid.");
        Assert.Equal(1, reader.GetInt32(2));
    }

    [Fact]
    public async Task EventCursorsPersistAndNeverRewind()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow;
        Assert.Empty(await repository.ReadEventCursorsAsync());

        await repository.SaveEventCursorsAsync([new EventCursor("System", 900, "hash-900", now)]);
        var stored = Assert.Single(await repository.ReadEventCursorsAsync());
        Assert.Equal(900, stored.Value.LastRecordId);
        Assert.Equal("hash-900", stored.Value.LastRecordHash);

        await repository.SaveEventCursorsAsync([new EventCursor("System", 880, "hash-880", now)]);
        Assert.Equal(900, (await repository.ReadEventCursorsAsync())["System"].LastRecordId);
        await repository.SaveEventCursorsAsync([new EventCursor("System", 940, "hash-940", now)]);
        Assert.Equal(940, (await repository.ReadEventCursorsAsync())["System"].LastRecordId);

        await repository.DeleteEventCursorAsync("System");
        Assert.Empty(await repository.ReadEventCursorsAsync());
    }

    [Fact]
    public async Task ClockReadingPersistsForBackwardJumpDetection()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        Assert.Null(await repository.ReadClockReadingAsync());
        var reading = DateTimeOffset.UtcNow.AddMinutes(-3);
        await repository.SaveClockReadingAsync(reading);
        Assert.Equal(reading, await repository.ReadClockReadingAsync());
        var later = reading.AddMinutes(2);
        await repository.SaveClockReadingAsync(later);
        Assert.Equal(later, await repository.ReadClockReadingAsync());
    }

    [Fact]
    public async Task RetentionSummaryIsPublishedWithTheSnapshot()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now,
            [SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 91, now)!], 7, []));

        var snapshot = await repository.ReadSnapshotAsync();
        var retention = Assert.IsType<AlertRetentionSummary>(snapshot.Retention);
        Assert.Equal(snapshot.TotalCount, retention.Retained);
        Assert.Equal(SecurityAlertRepository.MaximumAlertCount, retention.Capacity);
        Assert.Equal(TimeSpan.FromDays(30), retention.Window);
        Assert.NotNull(retention.OldestRetainedUtc);
        Assert.Empty(retention.Warnings);
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Retention = retention with { Retained = retention.Capacity + 1 } }));
    }

    [Fact]
    public async Task SnapshotListsSuppressionsWithHiddenCountsAndRearmsFromTheList()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow.AddMinutes(-4);
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 91, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [observation], 7, []));
        var alert = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);
        for (var confirmation = 0; confirmation < SecurityAlertRepository.FalsePositiveConfirmationThreshold; confirmation++)
            await repository.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "FalsePositive"));

        var snapshot = await repository.ReadSnapshotAsync();
        var listed = Assert.Single(snapshot.Suppressions!);
        Assert.Equal("Windows service installed", listed.Title.Split(':')[0]);
        Assert.False(string.IsNullOrEmpty(listed.AlertId));
        Assert.True(listed.MatchesSinceGrant >= 1);
        Assert.NotNull(listed.ExpiresUtc);
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));

        var rearm = await repository.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), listed.AlertId!, "Suppressed", "RearmFalsePositive"));
        Assert.Equal("rearmed", rearm.ResultCode);
        Assert.Empty((await repository.ReadSnapshotAsync()).Suppressions!);
    }

    [Fact]
    public void SnapshotValidationBoundsSuppressionRows()
    {
        var valid = new AlertSuppression(null, "Windows service installed", "System", 3, DateTimeOffset.UtcNow.AddDays(80), 4);
        var snapshot = new SecurityAlertSnapshot(1, DateTimeOffset.UtcNow, 0, [], [], null, [valid]);
        Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Suppressions = [valid with { AlertId = "not-an-id" }] }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Suppressions = [valid with { MatchesSinceGrant = -1 }] }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with { Suppressions = [valid with { Title = new string('t', 161) }] }));
        Assert.False(SecurityAlertClient.IsValidSnapshot(snapshot with
        {
            Suppressions = Enumerable.Range(0, 21).Select(index => valid with { Title = $"rule {index}" }).ToArray(),
        }));
    }

    [Fact]
    public async Task ExpiredSuppressionStopsHidingMatchesAndIsReported()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow.AddMinutes(-5);
        var observation = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 81, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [observation], 7, []));
        var alert = Assert.Single((await repository.ReadSnapshotAsync()).Alerts);
        for (var confirmation = 0; confirmation < SecurityAlertRepository.FalsePositiveConfirmationThreshold; confirmation++)
            await repository.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "FalsePositive"));

        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={database.Path};Pooling=False"))
        {
            await connection.OpenAsync();
            await using var expire = connection.CreateCommand();
            expire.CommandText = "UPDATE alert_fp_rules SET expires_at_utc=$past;";
            expire.Parameters.AddWithValue("$past", DateTimeOffset.UtcNow.AddDays(-1).ToString("O"));
            await expire.ExecuteNonQueryAsync();
        }

        var afterExpiry = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 82, now.AddMinutes(1))!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now.AddMinutes(1), [afterExpiry], 7, []));
        var snapshot = await repository.ReadSnapshotAsync();
        Assert.Equal("Open", snapshot.Alerts.Single(row => row.RecordId == 82).State);
        Assert.Contains(snapshot.Warnings, warning => warning.Contains("expired"));
    }

    [Fact]
    public async Task ExistingVersionOneAlertDatabaseMigratesToVersionTwo()
    {
        using var database = new TemporaryAlertDatabase();
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={database.Path};Pooling=False"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE alert_schema(version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 1)); INSERT INTO alert_schema VALUES(1);";
            await command.ExecuteNonQueryAsync();
        }
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        await using (var migrated = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={database.Path};Pooling=False"))
        {
            await migrated.OpenAsync();
            await using var verify = migrated.CreateCommand();
            verify.CommandText = "SELECT MAX(version) FROM alert_schema;";
            Assert.Equal(2L, (long)(await verify.ExecuteScalarAsync())!);
        }
    }

    [Fact]
    public async Task RearmingFingerprintDoesNotReopenAnIndividuallySuppressedAlert()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var now = DateTimeOffset.UtcNow.AddMinutes(-3);
        var first = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 61, now)!;
        var second = SecurityEventProvider.CreateObservation("System", "Service Control Manager", 7045, 62, now)!;
        await repository.IngestAsync(new SecurityEventSnapshot(1, now, [first, second], 7, []));
        var alerts = (await repository.ReadSnapshotAsync()).Alerts;
        var autoTarget = alerts.Single(alert => alert.RecordId == 61);
        var manualTarget = alerts.Single(alert => alert.RecordId == 62);
        var manuallySuppress = new AlertStateChangeRequest(1, Guid.NewGuid(), manualTarget.AlertId, "Open", "Suppressed");
        Assert.Equal("updated", (await repository.ChangeStateAsync(manuallySuppress)).ResultCode);

        for (var count = 0; count < 3; count++)
            await repository.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), autoTarget.AlertId, "Open", "FalsePositive"));
        Assert.Equal("Suppressed", (await repository.ReadSnapshotAsync()).Alerts.Single(alert => alert.AlertId == manualTarget.AlertId).State);

        var rearm = new AlertStateChangeRequest(1, Guid.NewGuid(), autoTarget.AlertId, "Suppressed", "RearmFalsePositive");
        Assert.Equal("rearmed", (await repository.ChangeStateAsync(rearm)).ResultCode);
        var final = (await repository.ReadSnapshotAsync()).Alerts;
        Assert.Equal("Open", final.Single(alert => alert.AlertId == autoTarget.AlertId).State);
        Assert.Equal("Suppressed", final.Single(alert => alert.AlertId == manualTarget.AlertId).State);
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
            // Generous retry window: under a loaded parallel test run the pipe servers can take seconds to come up.
            for (var attempt = 0; attempt < 50 && snapshot is null; attempt++)
            {
                snapshot = await client.TryGetSnapshotAsync();
                if (snapshot is null) await Task.Delay(200);
            }
            Assert.NotNull(snapshot);
            var alert = Assert.Single(snapshot.Alerts);
            AlertStateChangeResponse? response = null;
            for (var attempt = 0; attempt < 5 && response is null; attempt++)
            {
                // A fresh request ID per attempt: a timed-out client attempt never reached the server's replay ledger.
                response = await client.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, "Open", "Acknowledged"));
                if (response is null) await Task.Delay(300);
            }
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
        Assert.True(SecurityAlertClient.IsValidRequest(new AlertStateChangeRequest(1, Guid.NewGuid(), new string('a', 64), "Open", "FalsePositive")));
        Assert.False(SecurityAlertClient.IsValidRequest(new AlertStateChangeRequest(1, Guid.NewGuid(), new string('a', 64), "Suppressed", "FalsePositive")));
        Assert.True(SecurityAlertClient.IsValidRequest(new AlertStateChangeRequest(1, Guid.NewGuid(), new string('a', 64), "Suppressed", "RearmFalsePositive")));
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

    [Fact]
    public async Task RetentionSaysOutLoudWhatItsEvictionCountShows()
    {
        using var database = new TemporaryAlertDatabase();
        var repository = new SecurityAlertRepository(database.Path);
        await repository.InitializeAsync();
        var today = DateOnly.FromDateTime(DateTimeOffset.UtcNow.UtcDateTime).ToString("yyyy-MM-dd");
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={database.Path};Pooling=False"))
        {
            await connection.OpenAsync();
            await using var insert = connection.CreateCommand();
            insert.CommandText = "INSERT INTO alert_evictions(day,evicted) VALUES($day,5) ON CONFLICT(day) DO UPDATE SET evicted=evicted+5;";
            insert.Parameters.AddWithValue("$day", today);
            await insert.ExecuteNonQueryAsync();
        }

        var retention = (await repository.ReadSnapshotAsync()).Retention!;

        Assert.Equal(5, retention.EvictedLast7Days);
        Assert.Equal(0, retention.Retained);
        Assert.Empty((await repository.ReadSnapshotAsync()).Warnings);
        Assert.Contains(retention.Warnings, warning => warning.Contains("evicted in the last seven days", StringComparison.Ordinal));
        Assert.Contains("5", retention.Warnings.Single(warning => warning.Contains("evicted", StringComparison.Ordinal)));
    }

    internal sealed class TemporaryAlertDatabase : IDisposable
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
