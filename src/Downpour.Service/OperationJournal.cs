using System.Security.Principal;
using Microsoft.Data.Sqlite;

namespace Downpour.Service;

public enum JournalOperationKind { QuarantineFile, RestoreFile }
public enum JournalOperationState { Prepared, ContentStaged, Quarantined, RestorePrepared, Restored, RecoveryRequired, Failed }

public sealed record JournalOperation(
    Guid OperationId,
    JournalOperationKind Kind,
    JournalOperationState State,
    string ServiceSid,
    string PolicyVersion,
    string ObjectId,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record JournalEvent(
    long Sequence,
    Guid EventId,
    Guid OperationId,
    JournalOperationState? PreviousState,
    JournalOperationState State,
    string ResultCode,
    DateTimeOffset CreatedAtUtc);

/// <summary>
/// Durable intent and recovery journal. This records state only; it never performs or authorizes an action.
/// </summary>
public sealed class OperationJournal(string databasePath)
{
    public const int CurrentSchemaVersion = 2;
    private const int ObjectIdLength = 36;
    private const int MaxPolicyVersionLength = 48;
    private const int MaxResultCodeLength = 64;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public string DatabasePath { get; } = Path.GetFullPath(databasePath);

    public static OperationJournal CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var databasePath = Path.Combine(root, "operations.v1.db");
        SecureJournalDirectory.RestrictExistingFile(databasePath);
        SecureJournalDirectory.RestrictExistingFile(databasePath + "-wal");
        SecureJournalDirectory.RestrictExistingFile(databasePath + "-shm");
        return new OperationJournal(databasePath);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            EnsureDatabasePathIsNotReparsePoint();
            await using var connection = await OpenAsync(cancellationToken);
            var journalMode = await ScalarAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken);
            if (!string.Equals(Convert.ToString(journalMode), "wal", StringComparison.OrdinalIgnoreCase))
                throw new IOException("SQLite did not enable WAL mode for the operation journal.");
            await ExecuteAsync(connection, null, "PRAGMA synchronous=FULL;", cancellationToken);
            await using var transaction = connection.BeginTransaction();
            await ExecuteAsync(connection, transaction, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at_utc TEXT NOT NULL);", cancellationToken);
            var version = await ReadSchemaVersionAsync(connection, transaction, cancellationToken);
            if (version > CurrentSchemaVersion)
                throw new InvalidDataException($"Unsupported operation journal schema version {version}.");

            if (version < 1)
            {
                await ExecuteAsync(connection, transaction,
                    "CREATE TABLE IF NOT EXISTS operations (" +
                    "operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('QuarantineFile','RestoreFile')), " +
                    "state TEXT NOT NULL, actor_sid TEXT NOT NULL, policy_version TEXT NOT NULL, object_id TEXT NOT NULL, " +
                    "created_at_utc TEXT NOT NULL, updated_at_utc TEXT NOT NULL);" +
                    "CREATE TABLE IF NOT EXISTS operation_events (" +
                    "sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, operation_id TEXT NOT NULL, " +
                    "previous_state TEXT NULL, state TEXT NOT NULL, result_code TEXT NOT NULL, created_at_utc TEXT NOT NULL, " +
                    "FOREIGN KEY(operation_id) REFERENCES operations(operation_id));" +
                    "CREATE INDEX IF NOT EXISTS ix_operation_events_operation_sequence ON operation_events(operation_id, sequence);" +
                    "CREATE INDEX IF NOT EXISTS ix_operations_state_updated ON operations(state, updated_at_utc);" +
                    "CREATE TRIGGER IF NOT EXISTS operation_events_no_update BEFORE UPDATE ON operation_events BEGIN SELECT RAISE(ABORT,'operation events are append-only'); END;" +
                    "CREATE TRIGGER IF NOT EXISTS operation_events_no_delete BEFORE DELETE ON operation_events BEGIN SELECT RAISE(ABORT,'operation events are append-only'); END;" +
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at_utc) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ','now'));",
                    cancellationToken);
                version = 1;
            }

            if (version < 2)
            {
                await ExecuteAsync(connection, transaction, "ALTER TABLE operations RENAME COLUMN actor_sid TO service_sid;" +
                    "CREATE TRIGGER operations_state_insert_guard BEFORE INSERT ON operations WHEN NEW.state NOT IN ('Prepared','ContentStaged','Quarantined','RestorePrepared','Restored','RecoveryRequired','Failed') BEGIN SELECT RAISE(ABORT,'invalid operation state'); END;" +
                    "CREATE TRIGGER operations_state_update_guard BEFORE UPDATE OF state ON operations WHEN NEW.state NOT IN ('Prepared','ContentStaged','Quarantined','RestorePrepared','Restored','RecoveryRequired','Failed') BEGIN SELECT RAISE(ABORT,'invalid operation state'); END;" +
                    "CREATE TRIGGER operation_events_state_insert_guard BEFORE INSERT ON operation_events WHEN NEW.state NOT IN ('Prepared','ContentStaged','Quarantined','RestorePrepared','Restored','RecoveryRequired','Failed') OR (NEW.previous_state IS NOT NULL AND NEW.previous_state NOT IN ('Prepared','ContentStaged','Quarantined','RestorePrepared','Restored','RecoveryRequired','Failed')) BEGIN SELECT RAISE(ABORT,'invalid event state'); END;" +
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at_utc) VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ','now'));", cancellationToken);
                version = 2;
            }

            if (version != CurrentSchemaVersion)
                throw new InvalidDataException($"Unsupported operation journal schema version {version}.");
            await transaction.CommitAsync(cancellationToken);
        }
        finally { _gate.Release(); }
    }

    public async Task<JournalOperation> BeginAsync(
        Guid operationId,
        JournalOperationKind kind,
        string policyVersion,
        string objectId,
        Guid eventId,
        CancellationToken cancellationToken = default)
    {
        if (operationId == Guid.Empty || eventId == Guid.Empty) throw new ArgumentException("Operation and event IDs must be non-empty.");
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        ValidateBounded(policyVersion, MaxPolicyVersionLength, nameof(policyVersion));
        if (!IsValidObjectId(objectId))
            throw new ArgumentException("Object IDs must use the fixed obj- plus 32 lowercase hexadecimal characters format.", nameof(objectId));
        var serviceAccountSid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("The current service account SID is unavailable.");

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction();
            var existing = await ReadOperationAsync(connection, transaction, operationId, cancellationToken);
            if (existing is not null)
            {
                if (existing.Kind != kind || existing.ServiceSid != serviceAccountSid || existing.PolicyVersion != policyVersion || existing.ObjectId != objectId)
                    throw new InvalidOperationException("The operation ID is already bound to different intent.");
                var existingIntentEvent = await ReadEventByIdAsync(connection, transaction, eventId, cancellationToken);
                var initialEvent = await ReadInitialEventAsync(connection, transaction, operationId, cancellationToken);
                if (existingIntentEvent is null || initialEvent is null || initialEvent.EventId != eventId ||
                    initialEvent.State != JournalOperationState.Prepared || initialEvent.ResultCode != "intent-recorded")
                    throw new InvalidOperationException("The operation ID retry does not match its original intent event.");
                await transaction.CommitAsync(cancellationToken);
                return existing;
            }

            var now = DateTimeOffset.UtcNow;
            var operation = new JournalOperation(operationId, kind, JournalOperationState.Prepared, serviceAccountSid,
                policyVersion, objectId, now, now);
            await InsertOperationAsync(connection, transaction, operation, cancellationToken);
            await InsertEventAsync(connection, transaction, eventId, operationId, null,
                JournalOperationState.Prepared, "intent-recorded", now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return operation;
        }
        finally { _gate.Release(); }
    }

    public async Task<JournalOperation> TransitionAsync(
        Guid operationId,
        Guid eventId,
        JournalOperationState nextState,
        string resultCode,
        CancellationToken cancellationToken = default)
    {
        if (operationId == Guid.Empty || eventId == Guid.Empty) throw new ArgumentException("Operation and event IDs must be non-empty.");
        if (!Enum.IsDefined(nextState)) throw new ArgumentOutOfRangeException(nameof(nextState));
        ValidateBounded(resultCode, MaxResultCodeLength, nameof(resultCode));
        if (resultCode.Any(ch => !(char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or '.')))
            throw new ArgumentException("Result codes may contain only ASCII letters, digits, '.', '_' and '-'.", nameof(resultCode));

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction();
            var operation = await ReadOperationAsync(connection, transaction, operationId, cancellationToken)
                ?? throw new KeyNotFoundException("The operation does not exist.");
            var priorEvent = await ReadEventByIdAsync(connection, transaction, eventId, cancellationToken);
            if (priorEvent is not null)
            {
                if (priorEvent.OperationId != operationId || priorEvent.State != nextState || priorEvent.ResultCode != resultCode)
                    throw new InvalidOperationException("The event ID is already bound to a different transition.");
                await transaction.CommitAsync(cancellationToken);
                return operation;
            }

            if (!IsAllowed(operation.Kind, operation.State, nextState))
                throw new InvalidOperationException($"Transition {operation.State} -> {nextState} is not allowed for {operation.Kind}.");

            var now = DateTimeOffset.UtcNow;
            await UpdateStateAsync(connection, transaction, operationId, operation.State, nextState, now, cancellationToken);
            await InsertEventAsync(connection, transaction, eventId, operationId, operation.State, nextState, resultCode, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return operation with { State = nextState, UpdatedAtUtc = now };
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<JournalOperation>> GetPendingRecoveryAsync(int limit = 100, CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT operation_id, kind, state, service_sid, policy_version, object_id, created_at_utc, updated_at_utc FROM operations WHERE state IN ('Prepared','ContentStaged','RestorePrepared','RecoveryRequired','Failed') ORDER BY updated_at_utc LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", limit);
        var rows = new List<JournalOperation>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) rows.Add(ReadOperation(reader));
        return rows;
    }

    public async Task<IReadOnlyList<JournalEvent>> GetEventsAsync(Guid operationId, int limit = 500, CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 5000) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT sequence, event_id, operation_id, previous_state, state, result_code, created_at_utc FROM operation_events WHERE operation_id=$operationId ORDER BY sequence LIMIT $limit;";
        command.Parameters.AddWithValue("$operationId", operationId.ToString("D"));
        command.Parameters.AddWithValue("$limit", limit);
        var rows = new List<JournalEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            rows.Add(new JournalEvent(reader.GetInt64(0), Guid.Parse(reader.GetString(1)), Guid.Parse(reader.GetString(2)),
                reader.IsDBNull(3) ? null : Enum.Parse<JournalOperationState>(reader.GetString(3)),
                Enum.Parse<JournalOperationState>(reader.GetString(4)), reader.GetString(5), DateTimeOffset.Parse(reader.GetString(6))));
        return rows;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        EnsureDatabasePathIsNotReparsePoint();
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 5
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken);
            await ExecuteAsync(connection, null, "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL;", cancellationToken);
            return connection;
        }
        catch { await connection.DisposeAsync(); throw; }
    }

    private void EnsureDatabasePathIsNotReparsePoint()
    {
        var directory = Path.GetDirectoryName(DatabasePath) ?? throw new InvalidDataException("The journal database path has no parent directory.");
        Directory.CreateDirectory(directory);
        SecureJournalDirectory.ValidatePathAncestors(directory);
        if (File.Exists(DatabasePath) && (File.GetAttributes(DatabasePath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The journal database cannot be a reparse point.");
        foreach (var suffix in new[] { "-wal", "-shm" })
        {
            var sidecar = DatabasePath + suffix;
            if (File.Exists(sidecar) && (File.GetAttributes(sidecar) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Journal sidecar files cannot be reparse points.");
        }
    }

    private static bool IsAllowed(JournalOperationKind kind, JournalOperationState current, JournalOperationState next)
    {
        if (current is JournalOperationState.RecoveryRequired or JournalOperationState.Failed)
            return false; // Recovery requires a future typed verifier, not a caller-provided reason string.
        if (next is JournalOperationState.Failed or JournalOperationState.RecoveryRequired)
            return current is not (JournalOperationState.Quarantined or JournalOperationState.Restored or JournalOperationState.Failed);
        return (kind, current, next) switch
        {
            (JournalOperationKind.QuarantineFile, JournalOperationState.Prepared, JournalOperationState.ContentStaged) => true,
            (JournalOperationKind.QuarantineFile, JournalOperationState.ContentStaged, JournalOperationState.Quarantined) => true,
            (JournalOperationKind.RestoreFile, JournalOperationState.Prepared, JournalOperationState.RestorePrepared) => true,
            (JournalOperationKind.RestoreFile, JournalOperationState.RestorePrepared, JournalOperationState.Restored) => true,
            _ => false
        };
    }

    private static bool IsValidObjectId(string value) => value.Length == ObjectIdLength &&
        value.StartsWith("obj-", StringComparison.Ordinal) && value.Skip(4).All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void ValidateBounded(string value, int maxLength, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maxLength || value.Any(char.IsControl))
            throw new ArgumentException($"{name} is empty, too long, or contains control characters.", name);
    }

    private static async Task InsertOperationAsync(SqliteConnection connection, SqliteTransaction transaction, JournalOperation item, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO operations(operation_id,kind,state,service_sid,policy_version,object_id,created_at_utc,updated_at_utc) VALUES($id,$kind,$state,$sid,$policy,$object,$created,$updated);";
        command.Parameters.AddWithValue("$id", item.OperationId.ToString("D"));
        command.Parameters.AddWithValue("$kind", item.Kind.ToString());
        command.Parameters.AddWithValue("$state", item.State.ToString());
        command.Parameters.AddWithValue("$sid", item.ServiceSid);
        command.Parameters.AddWithValue("$policy", item.PolicyVersion);
        command.Parameters.AddWithValue("$object", item.ObjectId);
        command.Parameters.AddWithValue("$created", item.CreatedAtUtc.ToString("O"));
        command.Parameters.AddWithValue("$updated", item.UpdatedAtUtc.ToString("O"));
        await command.ExecuteNonQueryAsync(token);
    }

    private static async Task InsertEventAsync(SqliteConnection connection, SqliteTransaction transaction, Guid eventId, Guid operationId, JournalOperationState? previous, JournalOperationState state, string resultCode, DateTimeOffset now, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO operation_events(event_id,operation_id,previous_state,state,result_code,created_at_utc) VALUES($event,$operation,$previous,$state,$result,$created);";
        command.Parameters.AddWithValue("$event", eventId.ToString("D"));
        command.Parameters.AddWithValue("$operation", operationId.ToString("D"));
        command.Parameters.AddWithValue("$previous", previous?.ToString() is { } previousText ? previousText : DBNull.Value);
        command.Parameters.AddWithValue("$state", state.ToString());
        command.Parameters.AddWithValue("$result", resultCode);
        command.Parameters.AddWithValue("$created", now.ToString("O"));
        await command.ExecuteNonQueryAsync(token);
    }

    private static async Task UpdateStateAsync(SqliteConnection connection, SqliteTransaction transaction, Guid id, JournalOperationState current, JournalOperationState next, DateTimeOffset now, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE operations SET state=$next, updated_at_utc=$updated WHERE operation_id=$id AND state=$current;";
        command.Parameters.AddWithValue("$next", next.ToString());
        command.Parameters.AddWithValue("$updated", now.ToString("O"));
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        command.Parameters.AddWithValue("$current", current.ToString());
        if (await command.ExecuteNonQueryAsync(token) != 1) throw new InvalidOperationException("Operation state changed concurrently.");
    }

    private static async Task<JournalOperation?> ReadOperationAsync(SqliteConnection connection, SqliteTransaction transaction, Guid id, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT operation_id,kind,state,service_sid,policy_version,object_id,created_at_utc,updated_at_utc FROM operations WHERE operation_id=$id;";
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token) ? ReadOperation(reader) : null;
    }

    private static async Task<JournalEvent?> ReadEventByIdAsync(SqliteConnection connection, SqliteTransaction transaction, Guid id, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT sequence,event_id,operation_id,previous_state,state,result_code,created_at_utc FROM operation_events WHERE event_id=$id;";
        command.Parameters.AddWithValue("$id", id.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token)
            ? new JournalEvent(reader.GetInt64(0), Guid.Parse(reader.GetString(1)), Guid.Parse(reader.GetString(2)),
                reader.IsDBNull(3) ? null : Enum.Parse<JournalOperationState>(reader.GetString(3)), Enum.Parse<JournalOperationState>(reader.GetString(4)),
                reader.GetString(5), DateTimeOffset.Parse(reader.GetString(6))) : null;
    }

    private static async Task<JournalEvent?> ReadInitialEventAsync(SqliteConnection connection, SqliteTransaction transaction, Guid operationId, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT sequence,event_id,operation_id,previous_state,state,result_code,created_at_utc FROM operation_events WHERE operation_id=$id AND previous_state IS NULL ORDER BY sequence LIMIT 1;";
        command.Parameters.AddWithValue("$id", operationId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token)
            ? new JournalEvent(reader.GetInt64(0), Guid.Parse(reader.GetString(1)), Guid.Parse(reader.GetString(2)), null,
                Enum.Parse<JournalOperationState>(reader.GetString(4)), reader.GetString(5), DateTimeOffset.Parse(reader.GetString(6)))
            : null;
    }

    private static JournalOperation ReadOperation(SqliteDataReader reader) => new(
        Guid.Parse(reader.GetString(0)), Enum.Parse<JournalOperationKind>(reader.GetString(1)), Enum.Parse<JournalOperationState>(reader.GetString(2)),
        reader.GetString(3), reader.GetString(4), reader.GetString(5), DateTimeOffset.Parse(reader.GetString(6)), DateTimeOffset.Parse(reader.GetString(7)));

    private static async Task<int> ReadSchemaVersionAsync(SqliteConnection connection, SqliteTransaction? transaction, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COALESCE(MAX(version),0) FROM schema_migrations;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(token));
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, string sql, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync(token);
    }

    private static async Task ExecuteAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(token);
    }
}

internal static class SecureJournalDirectory
{
    public static void Ensure(string path)
    {
        ValidatePathAncestors(path);
        Directory.CreateDirectory(path);
        ValidatePathAncestors(path);
        var info = new DirectoryInfo(Path.GetFullPath(path));

        var userSid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The current Windows user SID is unavailable.");
        var security = info.GetAccessControl();
        Restrict(security, userSid, directory: true);
        info.SetAccessControl(security);
    }

    public static void RestrictExistingFile(string path)
    {
        if (!File.Exists(path)) return;
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Journal files cannot be reparse points.");
        var userSid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The current Windows user SID is unavailable.");
        var info = new FileInfo(path);
        var security = info.GetAccessControl();
        Restrict(security, userSid, directory: false);
        info.SetAccessControl(security);
    }

    public static void ValidatePathAncestors(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath) ?? throw new InvalidDataException("The journal path has no volume root.");
        var current = root;
        var relative = Path.GetRelativePath(root, fullPath);
        foreach (var component in relative.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            if (Directory.Exists(current) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("The journal path cannot pass through a reparse-point directory.");
        }
    }

    private static void Restrict(System.Security.AccessControl.FileSystemSecurity security, SecurityIdentifier userSid, bool directory)
    {
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                 security.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier)))
            security.RemoveAccessRuleSpecific(rule);
        security.SetOwner(userSid);
        var inheritance = directory
            ? System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit
            : System.Security.AccessControl.InheritanceFlags.None;
        security.SetAccessRule(new System.Security.AccessControl.FileSystemAccessRule(userSid,
            System.Security.AccessControl.FileSystemRights.FullControl, inheritance,
            System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        security.SetAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            System.Security.AccessControl.FileSystemRights.FullControl, inheritance,
            System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
    }
}

