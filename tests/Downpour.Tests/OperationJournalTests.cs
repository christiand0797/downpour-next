using Downpour.Service;
using Microsoft.Data.Sqlite;
using System.Security.Principal;

namespace Downpour.Tests;

public sealed class OperationJournalTests
{
    [Fact]
    public async Task JournalMigratesPersistsAndReopensWithOrderedEvents()
    {
        using var temp = new TemporaryDirectory();
        var path = Path.Combine(temp.Path, "state", "operations.db");
        var operationId = Guid.NewGuid();
        var beginEvent = Guid.NewGuid();
        var stageEvent = Guid.NewGuid();
        var commitEvent = Guid.NewGuid();

        var first = new OperationJournal(path);
        await first.InitializeAsync();
        var objectId = NewObjectId();
        var begun = await first.BeginAsync(operationId, JournalOperationKind.QuarantineFile, "policy-v1", objectId, beginEvent);
        Assert.Equal(JournalOperationState.Prepared, begun.State);
        Assert.Equal(JournalOperationState.ContentStaged,
            (await first.TransitionAsync(operationId, stageEvent, JournalOperationState.ContentStaged, "stage-verified")).State);
        Assert.Equal(JournalOperationState.Quarantined,
            (await first.TransitionAsync(operationId, commitEvent, JournalOperationState.Quarantined, "quarantine-committed")).State);

        var reopened = new OperationJournal(path);
        await reopened.InitializeAsync();
        var pending = await reopened.GetPendingRecoveryAsync();
        Assert.Empty(pending);
        var events = await reopened.GetEventsAsync(operationId);
        Assert.Equal(new[] { "Prepared", "ContentStaged", "Quarantined" }, events.Select(item => item.State.ToString()));
        Assert.Equal(new long[] { 1, 2, 3 }, events.Select(item => item.Sequence));
    }

    [Fact]
    public async Task JournalRejectsIllegalTransitionsAndPathLikeObjectIds()
    {
        using var temp = new TemporaryDirectory();
        var journal = new OperationJournal(Path.Combine(temp.Path, "operations.db"));
        await journal.InitializeAsync();
        var id = Guid.NewGuid();
        await journal.BeginAsync(id, JournalOperationKind.QuarantineFile, "policy-v1", NewObjectId(), Guid.NewGuid());

        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(id, Guid.NewGuid(), JournalOperationState.Quarantined, "skip-stage"));
        await Assert.ThrowsAsync<ArgumentException>(() => journal.BeginAsync(Guid.NewGuid(), JournalOperationKind.QuarantineFile, "policy-v1", "..\\secret", Guid.NewGuid()));
        Assert.Single(await journal.GetPendingRecoveryAsync());
    }

    [Fact]
    public async Task ReplayedEventIsIdempotentAndCannotBeRebound()
    {
        using var temp = new TemporaryDirectory();
        var journal = new OperationJournal(Path.Combine(temp.Path, "operations.db"));
        await journal.InitializeAsync();
        var id = Guid.NewGuid();
        await journal.BeginAsync(id, JournalOperationKind.QuarantineFile, "policy-v1", NewObjectId(), Guid.NewGuid());
        var transitionId = Guid.NewGuid();

        await journal.TransitionAsync(id, transitionId, JournalOperationState.ContentStaged, "stage-verified");
        var replay = await journal.TransitionAsync(id, transitionId, JournalOperationState.ContentStaged, "stage-verified");
        Assert.Equal(JournalOperationState.ContentStaged, replay.State);
        var events = await journal.GetEventsAsync(id);
        Assert.Equal(2, events.Count);
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(id, transitionId, JournalOperationState.Quarantined, "different-binding"));
    }

    [Fact]
    public async Task FailedEventInsertRollsBackStateProjection()
    {
        using var temp = new TemporaryDirectory();
        var journal = new OperationJournal(Path.Combine(temp.Path, "operations.db"));
        await journal.InitializeAsync();
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        await journal.BeginAsync(first, JournalOperationKind.QuarantineFile, "policy-v1", NewObjectId(), Guid.NewGuid());
        await journal.BeginAsync(second, JournalOperationKind.QuarantineFile, "policy-v1", NewObjectId(), Guid.NewGuid());
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = journal.DatabasePath, Pooling = false }.ToString()))
        {
            await connection.OpenAsync();
            await using var trigger = connection.CreateCommand();
            trigger.CommandText = $"CREATE TRIGGER fail_second_event BEFORE INSERT ON operation_events WHEN NEW.operation_id='{second:D}' BEGIN SELECT RAISE(ABORT,'injected test failure'); END;";
            await trigger.ExecuteNonQueryAsync();
        }

        await Assert.ThrowsAsync<SqliteException>(() => journal.TransitionAsync(second, Guid.NewGuid(), JournalOperationState.ContentStaged, "stage-verified"));
        Assert.Contains(await journal.GetPendingRecoveryAsync(), operation => operation.OperationId == second && operation.State == JournalOperationState.Prepared);
        Assert.Single(await journal.GetEventsAsync(second));
    }

    [Fact]
    public async Task JournalBoundsPageSizeAndAuditCodes()
    {
        using var temp = new TemporaryDirectory();
        var journal = new OperationJournal(Path.Combine(temp.Path, "operations.db"));
        await journal.InitializeAsync();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => journal.GetPendingRecoveryAsync(1001));
        var id = Guid.NewGuid();
        await journal.BeginAsync(id, JournalOperationKind.RestoreFile, "policy-v1", NewObjectId(), Guid.NewGuid());
        await Assert.ThrowsAsync<ArgumentException>(() => journal.TransitionAsync(id, Guid.NewGuid(), JournalOperationState.Quarantined, "path=C:\\temp"));
    }

    [Fact]
    public async Task InterruptedIntentRemainsVisibleAfterRestart()
    {
        using var temp = new TemporaryDirectory();
        var path = Path.Combine(temp.Path, "operations.db");
        var journal = new OperationJournal(path);
        await journal.InitializeAsync();
        var id = Guid.NewGuid();
        await journal.BeginAsync(id, JournalOperationKind.RestoreFile, "policy-v1", NewObjectId(), Guid.NewGuid());

        var reopened = new OperationJournal(path);
        await reopened.InitializeAsync();
        var pending = await reopened.GetPendingRecoveryAsync();
        Assert.Single(pending);
        Assert.Equal(id, pending[0].OperationId);
        Assert.Equal(JournalOperationState.Prepared, pending[0].State);
    }

    [Fact]
    public void JournalStateDirectoryUsesProtectedCurrentUserAndSystemAcl()
    {
        using var temp = new TemporaryDirectory();
        var path = Path.Combine(temp.Path, "state");
        SecureJournalDirectory.Ensure(path);
        var databasePath = Path.Combine(path, "operations.db");
        File.WriteAllText(databasePath, "test");
        SecureJournalDirectory.RestrictExistingFile(databasePath);
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            WindowsIdentity.GetCurrent().User!.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value
        };
        var directory = new DirectoryInfo(path);
        var directorySecurity = directory.GetAccessControl();
        Assert.True(directorySecurity.AreAccessRulesProtected);
        Assert.Equal(expected.Order(), directorySecurity.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .Select(rule => ((SecurityIdentifier)rule.IdentityReference).Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase).Order());
        var fileSecurity = new FileInfo(databasePath).GetAccessControl();
        Assert.True(fileSecurity.AreAccessRulesProtected);
        Assert.Equal(expected.Order(), fileSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .Select(rule => ((SecurityIdentifier)rule.IdentityReference).Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase).Order());
    }

    [Fact]
    public async Task FailedAndRecoveryRequiredOperationsStayPendingAndCannotBeGuessedComplete()
    {
        using var temp = new TemporaryDirectory();
        var journal = new OperationJournal(Path.Combine(temp.Path, "operations.db"));
        await journal.InitializeAsync();
        var recoveryId = Guid.NewGuid();
        var failedId = Guid.NewGuid();
        await journal.BeginAsync(recoveryId, JournalOperationKind.QuarantineFile, "policy-v1", NewObjectId(), Guid.NewGuid());
        await journal.TransitionAsync(recoveryId, Guid.NewGuid(), JournalOperationState.RecoveryRequired, "source-state-uncertain");
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(recoveryId, Guid.NewGuid(), JournalOperationState.Quarantined, "verified-by-caller"));
        await journal.BeginAsync(failedId, JournalOperationKind.RestoreFile, "policy-v1", NewObjectId(), Guid.NewGuid());
        await journal.TransitionAsync(failedId, Guid.NewGuid(), JournalOperationState.Failed, "restore-partial");
        var pending = await journal.GetPendingRecoveryAsync();
        Assert.Contains(pending, row => row.OperationId == recoveryId && row.State == JournalOperationState.RecoveryRequired);
        Assert.Contains(pending, row => row.OperationId == failedId && row.State == JournalOperationState.Failed);
    }

    [Fact]
    public async Task BeginReplayMustMatchOriginalIntentEvent()
    {
        using var temp = new TemporaryDirectory();
        var journal = new OperationJournal(Path.Combine(temp.Path, "operations.db"));
        await journal.InitializeAsync();
        var id = Guid.NewGuid();
        var objectId = NewObjectId();
        await journal.BeginAsync(id, JournalOperationKind.QuarantineFile, "policy-v1", objectId, Guid.NewGuid());

        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.BeginAsync(id, JournalOperationKind.QuarantineFile, "policy-v1", objectId, Guid.NewGuid()));
    }

    [Fact]
    public async Task SchemaV1MigratesToServiceIdentityV2WithoutDroppingPendingIntent()
    {
        using var temp = new TemporaryDirectory();
        var path = Path.Combine(temp.Path, "operations.db");
        var operationId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var objectId = NewObjectId();
        var serviceSid = WindowsIdentity.GetCurrent().User!.Value;
        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        Directory.CreateDirectory(temp.Path);
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_utc TEXT NOT NULL);" +
                "INSERT INTO schema_migrations(version,applied_at_utc) VALUES(1,'2026-10-04T00:00:00Z');" +
                "CREATE TABLE operations(operation_id TEXT PRIMARY KEY,kind TEXT NOT NULL,state TEXT NOT NULL,actor_sid TEXT NOT NULL,policy_version TEXT NOT NULL,object_id TEXT NOT NULL,created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL);" +
                "CREATE TABLE operation_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,operation_id TEXT NOT NULL,previous_state TEXT NULL,state TEXT NOT NULL,result_code TEXT NOT NULL,created_at_utc TEXT NOT NULL,FOREIGN KEY(operation_id) REFERENCES operations(operation_id));" +
                "INSERT INTO operations VALUES($id,'QuarantineFile','Prepared',$sid,'policy-v1',$object,$created,$updated);" +
                "INSERT INTO operation_events(event_id,operation_id,previous_state,state,result_code,created_at_utc) VALUES($event,$id,NULL,'Prepared','intent-recorded',$created);";
            command.Parameters.AddWithValue("$id", operationId.ToString("D"));
            command.Parameters.AddWithValue("$sid", serviceSid);
            command.Parameters.AddWithValue("$object", objectId);
            command.Parameters.AddWithValue("$created", timestamp);
            command.Parameters.AddWithValue("$updated", timestamp);
            command.Parameters.AddWithValue("$event", eventId.ToString("D"));
            await command.ExecuteNonQueryAsync();
        }

        var journal = new OperationJournal(path);
        await journal.InitializeAsync();
        var pending = await journal.GetPendingRecoveryAsync();
        Assert.Single(pending);
        Assert.Equal(serviceSid, pending[0].ServiceSid);
        Assert.Equal(objectId, pending[0].ObjectId);
    }

    [Theory]
    [InlineData("C:foo")]
    [InlineData("obj-../foo")]
    [InlineData("obj-%2f000000000000000000000000000000")]
    [InlineData("obj-0000000000000000000000000000000Ａ")]
    [InlineData("obj-0000000000000000000000000000000G")]
    public async Task BeginRejectsObjectIdsOutsideGeneratedTokenGrammar(string invalidId)
    {
        using var temp = new TemporaryDirectory();
        var journal = new OperationJournal(Path.Combine(temp.Path, "operations.db"));
        await journal.InitializeAsync();
        await Assert.ThrowsAsync<ArgumentException>(() => journal.BeginAsync(Guid.NewGuid(), JournalOperationKind.QuarantineFile, "policy-v1", invalidId, Guid.NewGuid()));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory() => Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "DownpourJournalTests", Guid.NewGuid().ToString("N"));
        public string Path { get; }
        public void Dispose()
        {
            if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true);
        }
    }

    private static string NewObjectId() => $"obj-{Guid.NewGuid():N}";
}


