using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Data.Sqlite;

namespace Downpour.Service;

/// <summary>Persists event-ID-backed alert observations and local triage state. It performs no system action.</summary>
public sealed class SecurityAlertRepository(string databasePath)
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumAlertCount = 10_000;
    public const int MaximumSnapshotAlerts = 512;
    private static readonly TimeSpan Retention = TimeSpan.FromDays(30);
    private static readonly HashSet<string> States = new(StringComparer.Ordinal)
        { "Open", "Acknowledged", "Suppressed" };
    private readonly SemaphoreSlim _gate = new(1, 1);

    public string DatabasePath { get; } = Path.GetFullPath(databasePath);

    public static SecurityAlertRepository CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var path = Path.Combine(root, "alerts.v1.db");
        SecureJournalDirectory.RestrictExistingFile(path);
        SecureJournalDirectory.RestrictExistingFile(path + "-wal");
        SecureJournalDirectory.RestrictExistingFile(path + "-shm");
        return new SecurityAlertRepository(path);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            EnsureSafePath();
            await using var connection = await OpenAsync(cancellationToken);
            var journalMode = await ScalarAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken);
            if (!string.Equals(Convert.ToString(journalMode), "wal", StringComparison.OrdinalIgnoreCase))
                throw new IOException("SQLite did not enable WAL mode for the alert store.");
            await ExecuteAsync(connection, "PRAGMA synchronous=FULL;", cancellationToken);
            await ExecuteAsync(connection,
                "CREATE TABLE IF NOT EXISTS alert_schema (version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 1));" +
                "INSERT INTO alert_schema(version) SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM alert_schema);" +
                "CREATE TABLE IF NOT EXISTS alerts (" +
                "alert_id TEXT PRIMARY KEY CHECK(length(alert_id)=64), dedup_key TEXT NOT NULL UNIQUE CHECK(length(dedup_key)<=512), " +
                "title TEXT NOT NULL CHECK(length(title)<=160), severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')), " +
                "technique TEXT NOT NULL CHECK(length(technique)<=32), log_name TEXT NOT NULL CHECK(length(log_name)<=128), " +
                "provider TEXT NOT NULL CHECK(length(provider)<=128), event_id INTEGER NOT NULL CHECK(event_id BETWEEN 0 AND 65535), " +
                "record_id INTEGER NULL CHECK(record_id IS NULL OR record_id>=0), event_time_utc TEXT NOT NULL, " +
                "first_seen_utc TEXT NOT NULL, last_seen_utc TEXT NOT NULL, occurrences INTEGER NOT NULL CHECK(occurrences BETWEEN 1 AND 100), " +
                "state TEXT NOT NULL CHECK(state IN ('Open','Acknowledged','Suppressed')));" +
                "CREATE INDEX IF NOT EXISTS ix_alerts_last_seen ON alerts(last_seen_utc DESC);" +
                "CREATE TABLE IF NOT EXISTS alert_state_events (" +
                "request_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, previous_state TEXT NOT NULL, next_state TEXT NOT NULL, " +
                "created_at_utc TEXT NOT NULL, FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE);",
                cancellationToken);
            var version = Convert.ToInt32(await ScalarAsync(connection, "SELECT MAX(version) FROM alert_schema;", cancellationToken));
            if (version != CurrentSchemaVersion)
                throw new InvalidDataException($"Unsupported alert store schema version {version}.");
        }
        finally { _gate.Release(); }
    }

    public async Task IngestAsync(SecurityEventSnapshot source, CancellationToken cancellationToken = default)
    {
        if (!SecurityEventClient.IsValidSnapshot(source))
            throw new InvalidDataException("The event snapshot did not pass its source contract validation.");

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction();
            foreach (var observation in source.Events)
            {
                var dedupKey = BuildDedupKey(observation);
                var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("downpour-alert-v1\0" + dedupKey))).ToLowerInvariant();
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    "INSERT INTO alerts(alert_id,dedup_key,title,severity,technique,log_name,provider,event_id,record_id,event_time_utc,first_seen_utc,last_seen_utc,occurrences,state) " +
                    "VALUES($id,$key,$title,$severity,$technique,$log,$provider,$event,$record,$eventTime,$firstSeen,$lastSeen,$occurrences,'Open') " +
                    "ON CONFLICT(dedup_key) DO UPDATE SET " +
                    "event_time_utc=MIN(alerts.event_time_utc,excluded.event_time_utc), " +
                    "record_id=COALESCE(excluded.record_id,alerts.record_id), " +
                    "last_seen_utc=excluded.last_seen_utc, occurrences=MAX(alerts.occurrences,excluded.occurrences);";
                command.Parameters.AddWithValue("$id", id);
                command.Parameters.AddWithValue("$key", dedupKey);
                command.Parameters.AddWithValue("$title", observation.Summary);
                command.Parameters.AddWithValue("$severity", observation.Severity);
                command.Parameters.AddWithValue("$technique", observation.Technique);
                command.Parameters.AddWithValue("$log", observation.LogName);
                command.Parameters.AddWithValue("$provider", observation.Provider);
                command.Parameters.AddWithValue("$event", observation.EventId);
                command.Parameters.AddWithValue("$record", (object?)observation.RecordId ?? DBNull.Value);
                command.Parameters.AddWithValue("$eventTime", observation.CreatedAtUtc!.Value.ToUniversalTime().ToString("O"));
                command.Parameters.AddWithValue("$firstSeen", source.CapturedAtUtc.ToUniversalTime().ToString("O"));
                command.Parameters.AddWithValue("$lastSeen", source.CapturedAtUtc.ToUniversalTime().ToString("O"));
                command.Parameters.AddWithValue("$occurrences", observation.Occurrences);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            await PruneAsync(connection, transaction, source.CapturedAtUtc.ToUniversalTime(), cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public async Task<SecurityAlertSnapshot> ReadSnapshotAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            var total = Convert.ToInt32(await ScalarAsync(connection, "SELECT COUNT(*) FROM alerts;", cancellationToken));
            var alerts = new List<SecurityAlert>(Math.Min(total, MaximumSnapshotAlerts));
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT alert_id,title,severity,technique,log_name,provider,event_id,record_id,event_time_utc,first_seen_utc,last_seen_utc,occurrences,state FROM alerts ORDER BY last_seen_utc DESC,alert_id LIMIT $limit;";
            command.Parameters.AddWithValue("$limit", MaximumSnapshotAlerts);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                alerts.Add(new SecurityAlert(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5), reader.GetInt32(6), reader.IsDBNull(7) ? null : reader.GetInt64(7),
                    ParseUtc(reader.GetString(8)), ParseUtc(reader.GetString(9)), ParseUtc(reader.GetString(10)), reader.GetInt32(11), reader.GetString(12)));
            }
            return new SecurityAlertSnapshot(1, DateTimeOffset.UtcNow, total, alerts, []);
        }
        finally { _gate.Release(); }
    }

    public async Task<AlertStateChangeResponse> ChangeStateAsync(
        AlertStateChangeRequest request, CancellationToken cancellationToken = default)
    {
        if (request.SchemaVersion != 1 || request.RequestId == Guid.Empty || !IsValidAlertId(request.AlertId) ||
            !States.Contains(request.ExpectedState) || !States.Contains(request.State))
            return new AlertStateChangeResponse(1, request.RequestId, false, "invalid-request");

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction();
            await using (var replay = connection.CreateCommand())
            {
                replay.Transaction = transaction;
                replay.CommandText = "SELECT alert_id,previous_state,next_state FROM alert_state_events WHERE request_id=$request;";
                replay.Parameters.AddWithValue("$request", request.RequestId.ToString("N"));
                await using var reader = await replay.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    var sameIntent = reader.GetString(0) == request.AlertId && reader.GetString(1) == request.ExpectedState && reader.GetString(2) == request.State;
                    await reader.DisposeAsync();
                    await transaction.CommitAsync(cancellationToken);
                    return new AlertStateChangeResponse(1, request.RequestId, sameIntent, sameIntent ? "replayed" : "request-id-conflict");
                }
            }

            var current = await ReadStateAsync(connection, transaction, request.AlertId, cancellationToken);
            if (current is null)
            {
                await transaction.CommitAsync(cancellationToken);
                return new AlertStateChangeResponse(1, request.RequestId, false, "alert-not-found");
            }
            if (current != request.ExpectedState)
            {
                await transaction.CommitAsync(cancellationToken);
                return new AlertStateChangeResponse(1, request.RequestId, false, "state-conflict");
            }
            if (!IsAllowedTransition(current, request.State))
            {
                await transaction.CommitAsync(cancellationToken);
                return new AlertStateChangeResponse(1, request.RequestId, false, "transition-denied");
            }
            if (current == request.State)
            {
                await transaction.CommitAsync(cancellationToken);
                return new AlertStateChangeResponse(1, request.RequestId, true, "unchanged");
            }

            var now = DateTimeOffset.UtcNow.ToString("O");
            await using (var update = connection.CreateCommand())
            {
                update.Transaction = transaction;
                update.CommandText = "UPDATE alerts SET state=$next WHERE alert_id=$id AND state=$previous;";
                update.Parameters.AddWithValue("$next", request.State);
                update.Parameters.AddWithValue("$id", request.AlertId);
                update.Parameters.AddWithValue("$previous", current);
                if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return new AlertStateChangeResponse(1, request.RequestId, false, "state-conflict");
                }
            }
            await using (var audit = connection.CreateCommand())
            {
                audit.Transaction = transaction;
                audit.CommandText = "INSERT INTO alert_state_events(request_id,alert_id,previous_state,next_state,created_at_utc) VALUES($request,$id,$previous,$next,$now);";
                audit.Parameters.AddWithValue("$request", request.RequestId.ToString("N"));
                audit.Parameters.AddWithValue("$id", request.AlertId);
                audit.Parameters.AddWithValue("$previous", current);
                audit.Parameters.AddWithValue("$next", request.State);
                audit.Parameters.AddWithValue("$now", now);
                await audit.ExecuteNonQueryAsync(cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
            return new AlertStateChangeResponse(1, request.RequestId, true, "updated");
        }
        finally { _gate.Release(); }
    }

    public static bool IsValidAlertId(string? value) => value is { Length: 64 } && value.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string BuildDedupKey(SecurityEventObservation observation)
    {
        if (observation.EventId == 4625)
        {
            var timestamp = observation.CreatedAtUtc!.Value.ToUniversalTime();
            var bucket = timestamp.UtcDateTime.Ticks / TimeSpan.FromMinutes(5).Ticks;
            return $"burst\0{observation.LogName}\0{observation.EventId}\0{bucket}";
        }
        if (observation.RecordId is { } recordId)
            return $"record\0{observation.LogName}\0{observation.EventId}\0{recordId}";
        var fallbackTime = observation.CreatedAtUtc!.Value.ToUniversalTime().ToString("yyyyMMddHHmm");
        return $"fallback\0{observation.LogName}\0{observation.Provider}\0{observation.EventId}\0{fallbackTime}";
    }

    private static bool IsAllowedTransition(string current, string next) => current == next || current switch
    {
        "Open" => next is "Acknowledged" or "Suppressed",
        "Acknowledged" => next is "Open" or "Suppressed",
        "Suppressed" => next == "Open",
        _ => false
    };

    private static async Task<string?> ReadStateAsync(SqliteConnection connection, SqliteTransaction transaction, string id, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT state FROM alerts WHERE alert_id=$id;";
        command.Parameters.AddWithValue("$id", id);
        var result = await command.ExecuteScalarAsync(token);
        return result is null or DBNull ? null : Convert.ToString(result);
    }

    private static async Task PruneAsync(SqliteConnection connection, SqliteTransaction transaction, DateTimeOffset now, CancellationToken token)
    {
        await using var expire = connection.CreateCommand();
        expire.Transaction = transaction;
        expire.CommandText = "DELETE FROM alerts WHERE last_seen_utc < $cutoff;";
        expire.Parameters.AddWithValue("$cutoff", now.Subtract(Retention).ToString("O"));
        await expire.ExecuteNonQueryAsync(token);
        await using var cap = connection.CreateCommand();
        cap.Transaction = transaction;
        cap.CommandText = "DELETE FROM alerts WHERE alert_id IN (SELECT alert_id FROM alerts ORDER BY last_seen_utc DESC,alert_id LIMIT -1 OFFSET $maximum);";
        cap.Parameters.AddWithValue("$maximum", MaximumAlertCount);
        await cap.ExecuteNonQueryAsync(token);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken token)
    {
        EnsureSafePath();
        SecureJournalDirectory.RestrictExistingFile(DatabasePath);
        SecureJournalDirectory.RestrictExistingFile(DatabasePath + "-wal");
        SecureJournalDirectory.RestrictExistingFile(DatabasePath + "-shm");
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 5
        }.ToString());
        await connection.OpenAsync(token);
        await ExecuteAsync(connection, "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;", token);
        return connection;
    }

    private void EnsureSafePath()
    {
        SecureJournalDirectory.ValidatePathAncestors(DatabasePath);
        if (File.Exists(DatabasePath) && (File.GetAttributes(DatabasePath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Alert database cannot be a reparse point.");
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, string sql, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync(token);
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(token);
    }

    private static DateTimeOffset ParseUtc(string value) => DateTimeOffset.Parse(value, System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
}
