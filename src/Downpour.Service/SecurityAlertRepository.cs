using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Data.Sqlite;

namespace Downpour.Service;

/// <summary>Persists event-ID-backed alert observations and local triage state. It performs no system action.</summary>
public sealed class SecurityAlertRepository(string databasePath)
{
    public const int CurrentSchemaVersion = 2;
    public const int FalsePositiveConfirmationThreshold = 3;
    /// <summary>A fingerprint suppression lapses after this long instead of hiding matches forever.</summary>
    public static readonly TimeSpan FalsePositiveSuppressionLifetime = SuppressionPolicy.DefaultLifetime;
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
                "CREATE TABLE IF NOT EXISTS alert_schema (version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 2));" +
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
                "created_at_utc TEXT NOT NULL, FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE);" +
                "CREATE TABLE IF NOT EXISTS alert_fp_rules (fingerprint TEXT PRIMARY KEY CHECK(length(fingerprint)=64), confirmations INTEGER NOT NULL CHECK(confirmations BETWEEN 1 AND 1000000), suppressed INTEGER NOT NULL CHECK(suppressed IN (0,1)), title TEXT NOT NULL CHECK(length(title)<=160), log_name TEXT NOT NULL CHECK(length(log_name)<=128), event_id INTEGER NOT NULL CHECK(event_id BETWEEN 0 AND 65535), first_seen_utc TEXT NOT NULL, last_seen_utc TEXT NOT NULL);" +
                "CREATE TABLE IF NOT EXISTS alert_fp_events (request_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, fingerprint TEXT NOT NULL, event_type TEXT NOT NULL CHECK(event_type IN ('confirm','rearm')), created_at_utc TEXT NOT NULL);" +
                "CREATE TABLE IF NOT EXISTS alert_fp_applied (alert_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);" +
                // Additive (no migration): user verification moves an item from Possible Threats to Threats, as in v29.
                "CREATE TABLE IF NOT EXISTS alert_verifications (alert_id TEXT PRIMARY KEY CHECK(length(alert_id)=64), verified_at_utc TEXT NOT NULL);" +
                // Additive (no migration): the classified indicator of a finding, so Threats can offer a matching response.
                "CREATE TABLE IF NOT EXISTS alert_indicators (alert_id TEXT PRIMARY KEY CHECK(length(alert_id)=64), " +
                "kind TEXT NOT NULL CHECK(kind IN ('file','ip','domain','hash')), value TEXT NOT NULL CHECK(length(value) BETWEEN 1 AND 512), " +
                "FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE);" +
                // Additive: evictions by day so capacity pressure is reported instead of silently losing evidence.
                "CREATE TABLE IF NOT EXISTS alert_evictions (day TEXT PRIMARY KEY, evicted INTEGER NOT NULL CHECK(evicted>=0));" +
                // Additive: per-channel ingestion cursors so a restart can say whether its quiet period is real.
                "CREATE TABLE IF NOT EXISTS event_cursors (log_name TEXT PRIMARY KEY CHECK(length(log_name)<=128), " +
                "last_record_id INTEGER NOT NULL CHECK(last_record_id>=0), last_hash TEXT NOT NULL CHECK(length(last_hash) BETWEEN 1 AND 128), " +
                "updated_utc TEXT NOT NULL);" +
                // Additive: one last clock reading, so a backward jump is detectable after a restart.
                "CREATE TABLE IF NOT EXISTS service_clock (id INTEGER PRIMARY KEY CHECK(id=1), last_utc TEXT NOT NULL);",
                cancellationToken);
            // Additive (no schema bump): suppression expiry and how many matches a suppression has hidden.
            await EnsureColumnAsync(connection, "alert_fp_rules", "expires_at_utc", "TEXT NULL", cancellationToken);
            await EnsureColumnAsync(connection, "alert_fp_rules", "matches_since_grant", "INTEGER NOT NULL DEFAULT 0", cancellationToken);
            var version = Convert.ToInt32(await ScalarAsync(connection, "SELECT MAX(version) FROM alert_schema;", cancellationToken));
            if (version == 1)
            {
                await ExecuteAsync(connection,
                    "DROP TABLE alert_schema; CREATE TABLE alert_schema(version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 2)); INSERT INTO alert_schema(version) VALUES(2);",
                    cancellationToken);
                version = 2;
            }
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
                var fingerprint = BuildFalsePositiveFingerprint(observation.LogName, observation.Provider, observation.EventId);
                var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("downpour-alert-v1\0" + dedupKey))).ToLowerInvariant();
                var suppressionActive = await IsFingerprintSuppressedAsync(connection, transaction, fingerprint, cancellationToken);
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    "INSERT INTO alerts(alert_id,dedup_key,title,severity,technique,log_name,provider,event_id,record_id,event_time_utc,first_seen_utc,last_seen_utc,occurrences,state) " +
                    "VALUES($id,$key,$title,$severity,$technique,$log,$provider,$event,$record,$eventTime,$firstSeen,$lastSeen,$occurrences,'Open') " +
                    "ON CONFLICT(dedup_key) DO UPDATE SET " +
                    "event_time_utc=MIN(alerts.event_time_utc,excluded.event_time_utc), " +
                    // A roll-up counts each newer record once; re-reading the same events never inflates the count.
                    "occurrences=CASE WHEN substr(alerts.dedup_key,1,6)='rollup' AND excluded.record_id > COALESCE(alerts.record_id,-1) " +
                    "THEN MIN(alerts.occurrences+1,1000000000) ELSE MAX(alerts.occurrences,excluded.occurrences) END, " +
                    "record_id=CASE WHEN substr(alerts.dedup_key,1,6)='rollup' THEN MAX(COALESCE(alerts.record_id,-1),COALESCE(excluded.record_id,-1)) " +
                    "ELSE COALESCE(excluded.record_id,alerts.record_id) END, " +
                    // Service installs are re-graded when their executable and signature are known (older rows lacked it).
                    "title=CASE WHEN alerts.event_id IN (7045,4697) AND excluded.title<>alerts.title THEN excluded.title ELSE alerts.title END, " +
                    "severity=CASE WHEN alerts.event_id IN (7045,4697) AND excluded.title<>alerts.title THEN excluded.severity ELSE alerts.severity END, " +
                    "last_seen_utc=excluded.last_seen_utc;";
                command.Parameters.AddWithValue("$id", id);
                command.Parameters.AddWithValue("$key", dedupKey);
                command.Parameters.AddWithValue("$title", Title(observation));
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
                // A service install's executable becomes the alert's file indicator, so Threats can offer quarantine.
                if (observation.FilePath is { Length: > 0 and <= 512 } file && Path.IsPathFullyQualified(file))
                {
                    await using var indicator = connection.CreateCommand();
                    indicator.Transaction = transaction;
                    indicator.CommandText = "INSERT INTO alert_indicators(alert_id,kind,value) VALUES($id,$kind,$value) " +
                        "ON CONFLICT(alert_id) DO UPDATE SET kind=excluded.kind, value=excluded.value;";
                    indicator.Parameters.AddWithValue("$id", id);
                    indicator.Parameters.AddWithValue("$kind", AlertIndicatorKinds.File);
                    indicator.Parameters.AddWithValue("$value", file);
                    await indicator.ExecuteNonQueryAsync(cancellationToken);
                }
                if (suppressionActive)
                    await ApplyFingerprintSuppressionAsync(connection, transaction, id, fingerprint, cancellationToken);
            }

            await PruneAsync(connection, transaction, source.CapturedAtUtc.ToUniversalTime(), cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public const int MaximumFindingsPerIngest = 512;

    /// <summary>The rule summary, plus the recorded detail for service installs ("Windows service installed: name · path · verdict").</summary>
    internal static string Title(SecurityEventObservation observation)
    {
        if (observation.Detail is not { Length: > 0 } detail) return observation.Summary;
        var title = $"{observation.Summary}: {detail}";
        return title.Length <= 160 ? title : title[..159] + "…";
    }

    /// <summary>
    /// Upserts posture/persistence findings as alerts. Identity lives in the provider column (see
    /// <see cref="SecurityFindingCatalog"/>), so deduplication and false-positive suppression are per finding.
    /// </summary>
    public async Task IngestFindingsAsync(IReadOnlyList<SecurityFindingObservation> findings, DateTimeOffset capturedAtUtc, CancellationToken cancellationToken = default)
    {
        if (findings.Count > MaximumFindingsPerIngest)
            throw new InvalidDataException("Too many findings in one ingest.");
        foreach (var finding in findings)
        {
            if (!SecurityFindingCatalog.Sources.Contains(finding.Source) || !SecurityFindingCatalog.Severities.Contains(finding.Severity) ||
                finding.Category is not { Length: > 0 and <= 128 } || finding.Technique is not { Length: > 0 and <= 32 } ||
                finding.Summary is not { Length: > 0 and <= 160 } || finding.Indicator is not { Length: <= 512 })
                throw new InvalidDataException("A finding did not pass its contract validation.");
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction();
            var seen = capturedAtUtc.ToUniversalTime().ToString("O");
            foreach (var finding in findings)
            {
                var identity = SecurityFindingMapper.Identity(finding);
                var dedupKey = $"finding|{finding.Source}|{identity}";
                var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("downpour-alert-v1\0" + dedupKey))).ToLowerInvariant();
                var fingerprint = BuildFalsePositiveFingerprint(finding.Source, identity, 0);
                var suppressionActive = await IsFingerprintSuppressedAsync(connection, transaction, fingerprint, cancellationToken);
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    "INSERT INTO alerts(alert_id,dedup_key,title,severity,technique,log_name,provider,event_id,record_id,event_time_utc,first_seen_utc,last_seen_utc,occurrences,state) " +
                    "VALUES($id,$key,$title,$severity,$technique,$log,$provider,0,NULL,$seen,$seen,$seen,1,'Open') " +
                    "ON CONFLICT(dedup_key) DO UPDATE SET title=excluded.title, severity=excluded.severity, technique=excluded.technique, last_seen_utc=excluded.last_seen_utc;";
                command.Parameters.AddWithValue("$id", id);
                command.Parameters.AddWithValue("$key", dedupKey);
                command.Parameters.AddWithValue("$title", finding.Summary);
                command.Parameters.AddWithValue("$severity", finding.Severity);
                command.Parameters.AddWithValue("$technique", finding.Technique);
                command.Parameters.AddWithValue("$log", finding.Source);
                command.Parameters.AddWithValue("$provider", identity);
                command.Parameters.AddWithValue("$seen", seen);
                await command.ExecuteNonQueryAsync(cancellationToken);
                if (AlertIndicatorKinds.Classify(finding.Source, finding.Indicator) is { } kind)
                {
                    await using var indicator = connection.CreateCommand();
                    indicator.Transaction = transaction;
                    indicator.CommandText = "INSERT INTO alert_indicators(alert_id,kind,value) VALUES($id,$kind,$value) " +
                        "ON CONFLICT(alert_id) DO UPDATE SET kind=excluded.kind, value=excluded.value;";
                    indicator.Parameters.AddWithValue("$id", id);
                    indicator.Parameters.AddWithValue("$kind", kind);
                    indicator.Parameters.AddWithValue("$value", finding.Indicator!.Trim());
                    await indicator.ExecuteNonQueryAsync(cancellationToken);
                }
                if (suppressionActive)
                    await ApplyFingerprintSuppressionAsync(connection, transaction, id, fingerprint, cancellationToken);
            }
            await PruneAsync(connection, transaction, capturedAtUtc.ToUniversalTime(), cancellationToken);
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
            command.CommandText = "SELECT a.alert_id,a.title,a.severity,a.technique,a.log_name,a.provider,a.event_id,a.record_id,a.event_time_utc,a.first_seen_utc,a.last_seen_utc,a.occurrences,a.state,v.alert_id IS NOT NULL,i.kind,i.value " +
                "FROM alerts a LEFT JOIN alert_verifications v ON v.alert_id=a.alert_id LEFT JOIN alert_indicators i ON i.alert_id=a.alert_id ORDER BY a.last_seen_utc DESC,a.alert_id LIMIT $limit;";
            command.Parameters.AddWithValue("$limit", MaximumSnapshotAlerts);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                alerts.Add(new SecurityAlert(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5), reader.GetInt32(6), reader.IsDBNull(7) ? null : reader.GetInt64(7),
                    ParseUtc(reader.GetString(8)), ParseUtc(reader.GetString(9)), ParseUtc(reader.GetString(10)), reader.GetInt32(11), reader.GetString(12),
                    reader.GetInt64(13) != 0, reader.IsDBNull(14) ? null : reader.GetString(14), reader.IsDBNull(15) ? null : reader.GetString(15)));
            }
            var suppressionWarnings = await ReadSuppressionWarningsAsync(connection, cancellationToken);
            var suppressions = await ReadSuppressionsAsync(connection, cancellationToken);
            var retention = await ReadRetentionAsync(connection, total, cancellationToken);
            return new SecurityAlertSnapshot(1, DateTimeOffset.UtcNow, total, alerts, suppressionWarnings,
                await ReadHourlyAsync(connection, cancellationToken), suppressions, retention);
        }
        finally { _gate.Release(); }
    }

    private static async Task<AlertRetentionSummary> ReadRetentionAsync(SqliteConnection connection, int retained, CancellationToken token)
    {
        DateTimeOffset? oldest = null;
        var oldestText = await ScalarAsync(connection, "SELECT MIN(last_seen_utc) FROM alerts;", token);
        if (oldestText is not null and not DBNull) oldest = ParseUtc(Convert.ToString(oldestText)!);
        var since = DateOnly.FromDateTime(DateTimeOffset.UtcNow.UtcDateTime.AddDays(-7)).ToString("yyyy-MM-dd");
        await using var evictions = connection.CreateCommand();
        evictions.CommandText = "SELECT COALESCE(SUM(evicted),0) FROM alert_evictions WHERE day >= $since;";
        evictions.Parameters.AddWithValue("$since", since);
        var evicted = Convert.ToInt32(await evictions.ExecuteScalarAsync(token));
        var report = StoreRetentionAccounting.Assess(retained, MaximumAlertCount, oldest, DateTimeOffset.UtcNow, Retention, []);
        return new AlertRetentionSummary(report.Retained, report.Capacity, report.OldestRetainedUtc, report.Window,
            evicted, report.Warnings.Take(4).ToArray());
    }

    /// <summary>The last wall-clock reading, used to detect a clock that moved backwards.</summary>
    public async Task<DateTimeOffset?> ReadClockReadingAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            var value = await ScalarAsync(connection, "SELECT last_utc FROM service_clock WHERE id=1;", cancellationToken);
            return value is null or DBNull ? null : ParseUtc(Convert.ToString(value)!);
        }
        finally { _gate.Release(); }
    }

    public async Task SaveClockReadingAsync(DateTimeOffset reading, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO service_clock(id,last_utc) VALUES(1,$at) " +
                "ON CONFLICT(id) DO UPDATE SET last_utc=excluded.last_utc;";
            command.Parameters.AddWithValue("$at", reading.ToUniversalTime().ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Ingestion cursors make the gap across a restart explicit instead of assumed.</summary>
    public async Task<IReadOnlyDictionary<string, EventCursor>> ReadEventCursorsAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT log_name,last_record_id,last_hash,updated_utc FROM event_cursors ORDER BY log_name LIMIT 64;";
            var cursors = new Dictionary<string, EventCursor>(StringComparer.OrdinalIgnoreCase);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                cursors[reader.GetString(0)] = new EventCursor(reader.GetString(0), reader.GetInt64(1), reader.GetString(2), ParseUtc(reader.GetString(3)));
            return cursors;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Drops one channel's cursor after its log was cleared, so numbering starts from the new baseline.</summary>
    public async Task DeleteEventCursorAsync(string logName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logName);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM event_cursors WHERE log_name=$log;";
            command.Parameters.AddWithValue("$log", logName);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Stores cursors monotonically: a replayed or stale record can never rewind ingestion.</summary>
    public async Task SaveEventCursorsAsync(IEnumerable<EventCursor> cursors, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(cursors);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction();
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                "INSERT INTO event_cursors(log_name,last_record_id,last_hash,updated_utc) VALUES($log,$id,$hash,$at) " +
                "ON CONFLICT(log_name) DO UPDATE SET last_record_id=excluded.last_record_id,last_hash=excluded.last_hash,updated_utc=excluded.updated_utc " +
                "WHERE excluded.last_record_id>event_cursors.last_record_id;";
            foreach (var cursor in cursors.Take(64))
            {
                command.Parameters.Clear();
                command.Parameters.AddWithValue("$log", cursor.LogName);
                command.Parameters.AddWithValue("$id", cursor.LastRecordId);
                command.Parameters.AddWithValue("$hash", cursor.LastRecordHash);
                command.Parameters.AddWithValue("$at", cursor.UpdatedUtc.ToUniversalTime().ToString("O"));
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// The active false-positive suppressions with how many matches each has hidden. The representative alert id points
    /// at a currently suppressed alert governed by the rule, so the existing audited Re-arm transition can clear it.
    /// </summary>
    private static async Task<IReadOnlyList<AlertSuppression>> ReadSuppressionsAsync(SqliteConnection connection, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT r.title,r.log_name,r.confirmations,r.expires_at_utc,r.matches_since_grant," +
            "(SELECT ap.alert_id FROM alert_fp_applied ap JOIN alerts a ON a.alert_id=ap.alert_id " +
            "WHERE ap.fingerprint=r.fingerprint AND a.state='Suppressed' LIMIT 1) " +
            "FROM alert_fp_rules r WHERE r.suppressed=1 ORDER BY r.matches_since_grant DESC,r.title LIMIT 20;";
        var suppressions = new List<AlertSuppression>(8);
        await using var reader = await command.ExecuteReaderAsync(token);
        while (await reader.ReadAsync(token))
        {
            var expires = reader.IsDBNull(3) ? (DateTimeOffset?)null : ParseUtc(reader.GetString(3));
            suppressions.Add(new AlertSuppression(
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.GetString(0), reader.GetString(1), reader.GetInt32(2), expires, reader.GetInt32(4)));
        }
        return suppressions;
    }

    /// <summary>Makes active and expired suppressions visible in the same place the alerts are reviewed.</summary>
    private static async Task<IReadOnlyList<string>> ReadSuppressionWarningsAsync(SqliteConnection connection, CancellationToken token)
    {
        var warnings = new List<string>(2);
        await using (var active = connection.CreateCommand())
        {
            active.CommandText = "SELECT COUNT(*) FROM alert_fp_rules WHERE suppressed=1 AND (expires_at_utc IS NULL OR expires_at_utc > $now);";
            active.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            var count = Convert.ToInt32(await active.ExecuteScalarAsync(token));
            if (count > 0) warnings.Add($"{count:N0} false-positive suppression(s) are active and hide new matches. They expire automatically; Re-arm clears one now.");
        }
        await using (var expired = connection.CreateCommand())
        {
            expired.CommandText = "SELECT COUNT(*),COALESCE(SUM(matches_since_grant),0) FROM alert_fp_rules WHERE suppressed=1 AND expires_at_utc IS NOT NULL AND expires_at_utc <= $now;";
            expired.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            await using var reader = await expired.ExecuteReaderAsync(token);
            if (await reader.ReadAsync(token) && reader.GetInt32(0) > 0)
                warnings.Add($"{reader.GetInt32(0):N0} suppression(s) have expired after hiding {reader.GetInt64(1):N0} match(es); they no longer hide new alerts and should be re-armed or left to lapse.");
        }
        return warnings;
    }

    public const int MaximumHourlyBuckets = 7 * 24 + 2;

    /// <summary>Per-hour counts for the last seven days by event time (stored as UTC ISO-8601, so the first 13 chars are the hour).</summary>
    private static async Task<IReadOnlyList<AlertHourCount>> ReadHourlyAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT substr(event_time_utc,1,13) AS hour, COUNT(*), SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) " +
            "FROM alerts WHERE event_time_utc >= $since GROUP BY hour ORDER BY hour DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$since", DateTimeOffset.UtcNow.AddDays(-7).AddHours(-1).ToString("O"));
        command.Parameters.AddWithValue("$limit", MaximumHourlyBuckets);
        var hours = new List<AlertHourCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (!DateTimeOffset.TryParseExact(reader.GetString(0) + ":00:00+00:00", "yyyy-MM-dd'T'HH:mm:sszzz",
                    System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var hour)) continue;
            hours.Add(new AlertHourCount(hour.ToUniversalTime(), reader.GetInt32(1), reader.GetInt32(2)));
        }
        return hours;
    }

    public async Task<AlertStateChangeResponse> ChangeStateAsync(
        AlertStateChangeRequest request, CancellationToken cancellationToken = default)
    {
        if (request.SchemaVersion != 1 || request.RequestId == Guid.Empty || !IsValidAlertId(request.AlertId) ||
            !States.Contains(request.ExpectedState) || !(States.Contains(request.State) || request.State is "FalsePositive" or "RearmFalsePositive" or "Verify" or "Unverify"))
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
            if (request.State is "FalsePositive" or "RearmFalsePositive")
            {
                var identity = await ReadFingerprintIdentityAsync(connection, transaction, request.AlertId, cancellationToken);
                if (identity is null)
                {
                    await transaction.CommitAsync(cancellationToken);
                    return new AlertStateChangeResponse(1, request.RequestId, false, "alert-not-found");
                }
                var replayFingerprint = BuildFalsePositiveFingerprint(identity.Value.LogName, identity.Value.Provider, identity.Value.EventId);
                await using var replay = connection.CreateCommand();
                replay.Transaction = transaction;
                replay.CommandText = "SELECT alert_id,fingerprint,event_type FROM alert_fp_events WHERE request_id=$request;";
                replay.Parameters.AddWithValue("$request", request.RequestId.ToString("N"));
                await using var replayReader = await replay.ExecuteReaderAsync(cancellationToken);
                if (await replayReader.ReadAsync(cancellationToken))
                {
                    var same = replayReader.GetString(0) == request.AlertId && replayReader.GetString(1) == replayFingerprint &&
                        replayReader.GetString(2) == (request.State == "FalsePositive" ? "confirm" : "rearm");
                    await replayReader.DisposeAsync();
                    await transaction.CommitAsync(cancellationToken);
                    return new AlertStateChangeResponse(1, request.RequestId, same, same ? "replayed" : "request-id-conflict");
                }
            }
            if (current != request.ExpectedState)
            {
                await transaction.CommitAsync(cancellationToken);
                return new AlertStateChangeResponse(1, request.RequestId, false, "state-conflict");
            }

            if (request.State is "FalsePositive" or "RearmFalsePositive")
            {
                if (request.State == "FalsePositive" && current is not ("Open" or "Acknowledged"))
                {
                    await transaction.CommitAsync(cancellationToken);
                    return new AlertStateChangeResponse(1, request.RequestId, false, "transition-denied");
                }
                var identity = await ReadFingerprintIdentityAsync(connection, transaction, request.AlertId, cancellationToken);
                if (identity is null)
                {
                    await transaction.CommitAsync(cancellationToken);
                    return new AlertStateChangeResponse(1, request.RequestId, false, "alert-not-found");
                }
                var fingerprint = BuildFalsePositiveFingerprint(identity.Value.LogName, identity.Value.Provider, identity.Value.EventId);
                var eventType = request.State == "FalsePositive" ? "confirm" : "rearm";
                var fpNow = DateTimeOffset.UtcNow.ToString("O");
                if (eventType == "confirm")
                {
                    await using var rule = connection.CreateCommand();
                    rule.Transaction = transaction;
                    rule.CommandText = "INSERT INTO alert_fp_rules(fingerprint,confirmations,suppressed,title,log_name,event_id,first_seen_utc,last_seen_utc,expires_at_utc,matches_since_grant) VALUES($fp,1,0,$title,$log,$event,$now,$now,NULL,0) ON CONFLICT(fingerprint) DO UPDATE SET confirmations=MIN(alert_fp_rules.confirmations+1,1000000),suppressed=CASE WHEN alert_fp_rules.suppressed=1 OR alert_fp_rules.confirmations+1 >= $threshold THEN 1 ELSE 0 END,last_seen_utc=excluded.last_seen_utc,expires_at_utc=CASE WHEN alert_fp_rules.suppressed=1 THEN alert_fp_rules.expires_at_utc WHEN alert_fp_rules.confirmations+1 >= $threshold THEN $expires ELSE NULL END;";
                    rule.Parameters.AddWithValue("$fp", fingerprint);
                    rule.Parameters.AddWithValue("$title", identity.Value.Title);
                    rule.Parameters.AddWithValue("$log", identity.Value.LogName);
                    rule.Parameters.AddWithValue("$event", identity.Value.EventId);
                    rule.Parameters.AddWithValue("$now", fpNow);
                    rule.Parameters.AddWithValue("$expires", DateTimeOffset.UtcNow.Add(FalsePositiveSuppressionLifetime).ToString("O"));
                    rule.Parameters.AddWithValue("$threshold", FalsePositiveConfirmationThreshold);
                    await rule.ExecuteNonQueryAsync(cancellationToken);
                }
                else
                {
                    await using var rule = connection.CreateCommand();
                    rule.Transaction = transaction;
                    rule.CommandText = "UPDATE alert_fp_rules SET suppressed=0,expires_at_utc=NULL,matches_since_grant=0 WHERE fingerprint=$fp;";
                    rule.Parameters.AddWithValue("$fp", fingerprint);
                    await rule.ExecuteNonQueryAsync(cancellationToken);
                    await using var reopen = connection.CreateCommand();
                    reopen.Transaction = transaction;
                    reopen.CommandText = "UPDATE alerts SET state='Open' WHERE alert_id IN (SELECT alert_id FROM alert_fp_applied WHERE fingerprint=$fp) AND state='Suppressed'; DELETE FROM alert_fp_applied WHERE fingerprint=$fp;";
                    reopen.Parameters.AddWithValue("$fp", fingerprint);
                    await reopen.ExecuteNonQueryAsync(cancellationToken);
                }
                await using (var audit = connection.CreateCommand())
                {
                    audit.Transaction = transaction;
                    audit.CommandText = "INSERT INTO alert_fp_events(request_id,alert_id,fingerprint,event_type,created_at_utc) VALUES($request,$id,$fp,$type,$now);";
                    audit.Parameters.AddWithValue("$request", request.RequestId.ToString("N"));
                    audit.Parameters.AddWithValue("$id", request.AlertId);
                    audit.Parameters.AddWithValue("$fp", fingerprint);
                    audit.Parameters.AddWithValue("$type", eventType);
                    audit.Parameters.AddWithValue("$now", fpNow);
                    await audit.ExecuteNonQueryAsync(cancellationToken);
                }
                if (eventType == "confirm")
                {
                    await using var suppress = connection.CreateCommand();
                    suppress.Transaction = transaction;
                    suppress.CommandText = "INSERT OR IGNORE INTO alert_fp_applied(alert_id,fingerprint) SELECT alert_id,$fp FROM alerts WHERE log_name=$log AND event_id=$event AND provider=$provider AND state IN ('Open','Acknowledged') AND EXISTS(SELECT 1 FROM alert_fp_rules WHERE fingerprint=$fp AND suppressed=1); UPDATE alerts SET state='Suppressed' WHERE alert_id IN (SELECT alert_id FROM alert_fp_applied WHERE fingerprint=$fp) AND state IN ('Open','Acknowledged');";
                    suppress.Parameters.AddWithValue("$log", identity.Value.LogName);
                    suppress.Parameters.AddWithValue("$event", identity.Value.EventId);
                    suppress.Parameters.AddWithValue("$provider", identity.Value.Provider);
                    suppress.Parameters.AddWithValue("$fp", fingerprint);
                    await suppress.ExecuteNonQueryAsync(cancellationToken);
                    // Count the alerts this suppression just hid; later ingestions add one each through the helper.
                    await using var applied = connection.CreateCommand();
                    applied.Transaction = transaction;
                    applied.CommandText = "UPDATE alert_fp_rules SET matches_since_grant=(SELECT COUNT(*) FROM alert_fp_applied WHERE fingerprint=$fp) WHERE fingerprint=$fp;";
                    applied.Parameters.AddWithValue("$fp", fingerprint);
                    await applied.ExecuteNonQueryAsync(cancellationToken);
                }
                await PruneFalsePositiveEventsAsync(connection, transaction, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                await using var summary = connection.CreateCommand();
                summary.CommandText = "SELECT confirmations,suppressed FROM alert_fp_rules WHERE fingerprint=$fp;";
                summary.Parameters.AddWithValue("$fp", fingerprint);
                await using var summaryReader = await summary.ExecuteReaderAsync(cancellationToken);
                await summaryReader.ReadAsync(cancellationToken);
                var count = summaryReader.GetInt32(0);
                var suppressed = summaryReader.GetInt32(1) != 0;
                return new AlertStateChangeResponse(1, request.RequestId, true,
                    eventType == "rearm" ? "rearmed" : suppressed ? "fingerprint-suppressed" : $"confirmed-{Math.Min(count, FalsePositiveConfirmationThreshold)}");
            }
            if (request.State is "Verify" or "Unverify")
                return await ChangeVerificationAsync(connection, transaction, request, current, cancellationToken);
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

    /// <summary>Verify promotes an Open/Acknowledged item to Threats; Unverify returns it to Possible Threats. Both are audited and replay-safe.</summary>
    private static async Task<AlertStateChangeResponse> ChangeVerificationAsync(
        SqliteConnection connection, SqliteTransaction transaction, AlertStateChangeRequest request, string current, CancellationToken token)
    {
        if (request.State == "Verify" && current is not ("Open" or "Acknowledged"))
        {
            await transaction.CommitAsync(token);
            return new AlertStateChangeResponse(1, request.RequestId, false, "transition-denied");
        }
        var now = DateTimeOffset.UtcNow.ToString("O");
        await using (var change = connection.CreateCommand())
        {
            change.Transaction = transaction;
            change.CommandText = request.State == "Verify"
                ? "INSERT OR IGNORE INTO alert_verifications(alert_id,verified_at_utc) VALUES($id,$now);"
                : "DELETE FROM alert_verifications WHERE alert_id=$id;";
            change.Parameters.AddWithValue("$id", request.AlertId);
            change.Parameters.AddWithValue("$now", now);
            await change.ExecuteNonQueryAsync(token);
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
            await audit.ExecuteNonQueryAsync(token);
        }
        await transaction.CommitAsync(token);
        return new AlertStateChangeResponse(1, request.RequestId, true, request.State == "Verify" ? "verified" : "unverified");
    }

    public static bool IsValidAlertId(string? value) => value is { Length: 64 } && value.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static string BuildFalsePositiveFingerprint(string logName, string provider, int eventId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"downpour-alert-fp-v1\0{logName.Trim().ToUpperInvariant()}\0{provider.Trim().ToUpperInvariant()}\0{eventId}"))).ToLowerInvariant();

    /// <summary>
    /// True only while a fingerprint suppression is active. An expired suppression stops hiding new matches instead of
    /// silently continuing: expiry is the whole reason the record carries a timestamp.
    /// </summary>
    private static async Task<bool> IsFingerprintSuppressedAsync(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT suppressed,expires_at_utc FROM alert_fp_rules WHERE fingerprint=$fp;";
        command.Parameters.AddWithValue("$fp", fingerprint);
        await using var reader = await command.ExecuteReaderAsync(token);
        if (!await reader.ReadAsync(token) || reader.GetInt32(0) != 1) return false;
        if (reader.IsDBNull(1)) return true;
        return DateTimeOffset.TryParse(reader.GetString(1), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind, out var expires) && DateTimeOffset.UtcNow < expires;
    }

    private static async Task ApplyFingerprintSuppressionAsync(SqliteConnection connection, SqliteTransaction transaction, string alertId, string fingerprint, CancellationToken token)
    {
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = "UPDATE alerts SET state='Suppressed' WHERE alert_id=$id AND state IN ('Open','Acknowledged');";
        update.Parameters.AddWithValue("$id", alertId);
        if (await update.ExecuteNonQueryAsync(token) != 1) return;
        await using var mark = connection.CreateCommand();
        mark.Transaction = transaction;
        mark.CommandText = "INSERT OR IGNORE INTO alert_fp_applied(alert_id,fingerprint) VALUES($id,$fp);";
        mark.Parameters.AddWithValue("$id", alertId);
        mark.Parameters.AddWithValue("$fp", fingerprint);
        await mark.ExecuteNonQueryAsync(token);
        // Count what the suppression is actually hiding, so a suppression that hides CRITICAL matches can be flagged.
        await using var count = connection.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = "UPDATE alert_fp_rules SET matches_since_grant=MIN(matches_since_grant+1,1000000) WHERE fingerprint=$fp AND suppressed=1;";
        count.Parameters.AddWithValue("$fp", fingerprint);
        await count.ExecuteNonQueryAsync(token);
    }

    private static async Task EnsureColumnAsync(SqliteConnection connection, string table, string column, string definition, CancellationToken token)
    {
        await using var probe = connection.CreateCommand();
        probe.CommandText = $"SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name='{column}';";
        if (Convert.ToInt32(await probe.ExecuteScalarAsync(token)) > 0) return;
        await ExecuteAsync(connection, $"ALTER TABLE {table} ADD COLUMN {column} {definition};", token);
    }

    private static async Task<(string Title, string LogName, string Provider, int EventId)?> ReadFingerprintIdentityAsync(SqliteConnection connection, SqliteTransaction transaction, string alertId, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT title,log_name,provider,event_id FROM alerts WHERE alert_id=$id;";
        command.Parameters.AddWithValue("$id", alertId);
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token) ? (reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3)) : null;
    }

    private static bool IsRollupEvent(string logName, int eventId) =>
        (logName.Equals("Microsoft-Windows-PowerShell/Operational", StringComparison.OrdinalIgnoreCase) && eventId == 4104) ||
        (logName.Equals("Security", StringComparison.OrdinalIgnoreCase) && eventId is 4688 or 4663 or 4672 or 4673);

    private static string BuildDedupKey(SecurityEventObservation observation)
    {
        if (observation.EventId == 4625)
        {
            var timestamp = observation.CreatedAtUtc!.Value.ToUniversalTime();
            var bucket = timestamp.UtcDateTime.Ticks / TimeSpan.FromMinutes(5).Ticks;
            return $"burst\0{observation.LogName}\0{observation.EventId}\0{bucket}";
        }
        // Sysmon record IDs can restart after a log clear. Keep distinct event times distinct.
        if (observation.LogName.Equals(SysmonCatalog.LogName, StringComparison.OrdinalIgnoreCase) && observation.RecordId is { } sysmonRecord)
            return $"sysmon\0{observation.EventId}\0{sysmonRecord}\0{observation.CreatedAtUtc!.Value.UtcTicks}";
        // High-volume informational events become one alert per event type per hour instead of one per record.
        if (observation.RecordId is not null && IsRollupEvent(observation.LogName, observation.EventId))
        {
            var hour = observation.CreatedAtUtc!.Value.ToUniversalTime().ToString("yyyyMMddHH");
            return $"rollup\0{observation.LogName}\0{observation.EventId}\0{hour}";
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
        var evicted = await expire.ExecuteNonQueryAsync(token);
        await using var cap = connection.CreateCommand();
        cap.Transaction = transaction;
        cap.CommandText = "DELETE FROM alerts WHERE alert_id IN (SELECT alert_id FROM alerts ORDER BY last_seen_utc DESC,alert_id LIMIT -1 OFFSET $maximum);";
        cap.Parameters.AddWithValue("$maximum", MaximumAlertCount);
        evicted += await cap.ExecuteNonQueryAsync(token);
        if (evicted > 0)
        {
            await using var record = connection.CreateCommand();
            record.Transaction = transaction;
            record.CommandText = "INSERT INTO alert_evictions(day,evicted) VALUES($day,$count) " +
                "ON CONFLICT(day) DO UPDATE SET evicted=evicted+$count;";
            record.Parameters.AddWithValue("$day", DateOnly.FromDateTime(now.UtcDateTime).ToString("yyyy-MM-dd"));
            record.Parameters.AddWithValue("$count", evicted);
            await record.ExecuteNonQueryAsync(token);
        }
        await using var markers = connection.CreateCommand();
        markers.Transaction = transaction;
        markers.CommandText = "DELETE FROM alert_fp_applied WHERE NOT EXISTS(SELECT 1 FROM alerts WHERE alerts.alert_id=alert_fp_applied.alert_id);" +
            "DELETE FROM alert_verifications WHERE NOT EXISTS(SELECT 1 FROM alerts WHERE alerts.alert_id=alert_verifications.alert_id);";
        await markers.ExecuteNonQueryAsync(token);
    }

    private static async Task PruneFalsePositiveEventsAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken token)
    {
        await using var prune = connection.CreateCommand();
        prune.Transaction = transaction;
        prune.CommandText = "DELETE FROM alert_fp_events WHERE created_at_utc < $cutoff; DELETE FROM alert_fp_events WHERE request_id IN (SELECT request_id FROM alert_fp_events ORDER BY created_at_utc DESC,request_id LIMIT -1 OFFSET $maximum);";
        prune.Parameters.AddWithValue("$cutoff", DateTimeOffset.UtcNow.Subtract(TimeSpan.FromDays(30)).ToString("O"));
        prune.Parameters.AddWithValue("$maximum", 10_000);
        await prune.ExecuteNonQueryAsync(token);
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
