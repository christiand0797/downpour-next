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
        var begun = await first.BeginAsync(operationId, JournalOperationKind.QuarantineFile, "policy-v1", "obj-001", beginEvent);
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
        await journal.BeginAsync(id, JournalOperationKind.QuarantineFile, "policy-v1", "obj-002", Guid.NewGuid());

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
        await journal.BeginAsync(id, JournalOperationKind.QuarantineFile, "policy-v1", "obj-003", Guid.NewGuid());
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
        await journal.BeginAsync(first, JournalOperationKind.QuarantineFile, "policy-v1", "obj-004", Guid.NewGuid());
        await journal.BeginAsync(second, JournalOperationKind.QuarantineFile, "policy-v1", "obj-005", Guid.NewGuid());
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
        await journal.BeginAsync(id, JournalOperationKind.RestoreFile, "policy-v1", "obj-006", Guid.NewGuid());
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
        await journal.BeginAsync(id, JournalOperationKind.RestoreFile, "policy-v1", "obj-007", Guid.NewGuid());

        var reopened = new OperationJournal(path);
        await reopened.InitializeAsync();
        var pending = await reopened.GetPendingRecoveryAsync();
        Assert.Single(pending);
        Assert.Equal(id, pending[0].OperationId);
        Assert.Equal(JournalOperationState.Prepared, pending[0].State);
    }

    [Fact]
    public async Task ProductionJournalUsesProtectedCurrentUserAndSystemAcl()
    {
        var journal = OperationJournal.CreateForCurrentUser();
        await journal.InitializeAsync();
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            WindowsIdentity.GetCurrent().User!.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value
        };
        var directory = new DirectoryInfo(Path.GetDirectoryName(journal.DatabasePath)!);
        var directorySecurity = directory.GetAccessControl();
        Assert.True(directorySecurity.AreAccessRulesProtected);
        Assert.Equal(expected.Order(), directorySecurity.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .Select(rule => ((SecurityIdentifier)rule.IdentityReference).Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase).Order());
        var fileSecurity = new FileInfo(journal.DatabasePath).GetAccessControl();
        Assert.Equal(expected.Order(), fileSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .Select(rule => ((SecurityIdentifier)rule.IdentityReference).Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase).Order());
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
}


