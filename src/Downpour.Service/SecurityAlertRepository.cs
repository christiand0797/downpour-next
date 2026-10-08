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
                "FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE);",
                cancellationToken);
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
            return new SecurityAlertSnapshot(1, DateTimeOffset.UtcNow, total, alerts, []);
        }
        finally { _gate.Release(); }
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
                    rule.CommandText = "INSERT INTO alert_fp_rules(fingerprint,confirmations,suppressed,title,log_name,event_id,first_seen_utc,last_seen_utc) VALUES($fp,1,0,$title,$log,$event,$now,$now) ON CONFLICT(fingerprint) DO UPDATE SET confirmations=MIN(alert_fp_rules.confirmations+1,1000000),suppressed=CASE WHEN alert_fp_rules.suppressed=1 OR alert_fp_rules.confirmations+1 >= $threshold THEN 1 ELSE 0 END,last_seen_utc=excluded.last_seen_utc;";
                    rule.Parameters.AddWithValue("$fp", fingerprint);
                    rule.Parameters.AddWithValue("$title", identity.Value.Title);
                    rule.Parameters.AddWithValue("$log", identity.Value.LogName);
                    rule.Parameters.AddWithValue("$event", identity.Value.EventId);
                    rule.Parameters.AddWithValue("$now", fpNow);
                    rule.Parameters.AddWithValue("$threshold", FalsePositiveConfirmationThreshold);
                    await rule.ExecuteNonQueryAsync(cancellationToken);
                }
                else
                {
                    await using var rule = connection.CreateCommand();
                    rule.Transaction = transaction;
                    rule.CommandText = "UPDATE alert_fp_rules SET suppressed=0 WHERE fingerprint=$fp;";
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

    private static async Task<bool> IsFingerprintSuppressedAsync(SqliteConnection connection, SqliteTransaction transaction, string fingerprint, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT suppressed FROM alert_fp_rules WHERE fingerprint=$fp;";
        command.Parameters.AddWithValue("$fp", fingerprint);
        var result = await command.ExecuteScalarAsync(token);
        return result is not null and not DBNull && Convert.ToInt32(result) == 1;
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
        await expire.ExecuteNonQueryAsync(token);
        await using var cap = connection.CreateCommand();
        cap.Transaction = transaction;
        cap.CommandText = "DELETE FROM alerts WHERE alert_id IN (SELECT alert_id FROM alerts ORDER BY last_seen_utc DESC,alert_id LIMIT -1 OFFSET $maximum);";
        cap.Parameters.AddWithValue("$maximum", MaximumAlertCount);
        await cap.ExecuteNonQueryAsync(token);
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
