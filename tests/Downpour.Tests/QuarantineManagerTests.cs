using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public class QuarantineManagerTests : IDisposable
{
    private readonly string _tempJournalPath;
    private readonly OperationJournal _journal;
    private readonly QuarantineManager _manager;

    public QuarantineManagerTests()
    {
        _tempJournalPath = Path.Combine(Path.GetTempPath(), $"downpour-journal-{Guid.NewGuid():N}");
        var journalPath = Path.Combine(_tempJournalPath, "operations.v1.db");
        _journal = new OperationJournal(journalPath);
        _manager = new QuarantineManager(_journal, NullLogger<QuarantineManager>.Instance);
    }

    private static string CreateTempFile(string content = "test content")
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"test-{Guid.NewGuid():N}.txt");
        File.WriteAllText(tempFile, content);
        return tempFile;
    }

    private static void DeleteTempFile(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static async Task<string> ComputeFileHashAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hashBytes = await Task.Run(() => sha256.ComputeHash(stream));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempJournalPath))
        {
            try
            {
                Directory.Delete(_tempJournalPath, recursive: true);
            }
            catch { /* Ignore cleanup failures */ }
        }
    }

    [Fact]
    public async Task PrepareQuarantineAsync_WithValidRequest_ReturnsAccepted()
    {
        // Arrange
        await _journal.InitializeAsync();

        var tempFile = CreateTempFile();
        var hash = await ComputeFileHashAsync(tempFile);

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", tempFile },
                { "expectedHash", hash }
            });

        try
        {
            // Act
            var response = await _manager.PrepareQuarantineAsync(request);

            // Assert
            Assert.True(response.Accepted);
            Assert.Equal(ActionResultCodes.Accepted, response.ResultCode);
            Assert.NotNull(response.OperationId);
            Assert.True(Guid.TryParse(response.OperationId, out _));
            Assert.Contains("computedHash", response.Details.Keys);
        }
        finally
        {
            DeleteTempFile(tempFile);
        }
    }

    [Fact]
    public async Task PrepareQuarantineAsync_WithMissingParameter_ReturnsRejected()
    {
        // Arrange
        await _journal.InitializeAsync();

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\Temp\test.exe" }
                // Missing expectedHash
            });

        // Act
        var response = await _manager.PrepareQuarantineAsync(request);

        // Assert
        Assert.False(response.Accepted);
        Assert.Equal(ActionResultCodes.ParameterInvalid, response.ResultCode);
        Assert.Contains("error", response.Details.Keys);
    }

    [Fact]
    public async Task PrepareQuarantineAsync_WithHashMismatch_ReturnsRejected()
    {
        // Arrange
        await _journal.InitializeAsync();

        var tempFile = CreateTempFile();

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", tempFile },
                { "expectedHash", "wronghash" }
            });

        try
        {
            // Act
            var response = await _manager.PrepareQuarantineAsync(request);

            // Assert
            Assert.False(response.Accepted);
            Assert.Equal(ActionResultCodes.ParameterInvalid, response.ResultCode);
            Assert.Contains("Hash mismatch", response.Details["error"]);
        }
        finally
        {
            DeleteTempFile(tempFile);
        }
    }

    [Fact]
    public async Task PrepareQuarantineAsync_WithInvalidPath_ReturnsRejected()
    {
        // Arrange
        await _journal.InitializeAsync();

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"..\..\..\etc\passwd" }, // Traversal attempt
                { "expectedHash", "abc123" }
            });

        // Act
        var response = await _manager.PrepareQuarantineAsync(request);

        // Assert
        Assert.False(response.Accepted);
        Assert.Equal(ActionResultCodes.ObjectIdInvalid, response.ResultCode);
        Assert.Contains("traversal", response.Details["error"], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PrepareQuarantineAsync_WithNonExistentFile_ReturnsRejected()
    {
        // Arrange
        await _journal.InitializeAsync();

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", @"C:\NonExistent\file.exe" },
                { "expectedHash", "abc123" }
            });

        // Act
        var response = await _manager.PrepareQuarantineAsync(request);

        // Assert
        Assert.False(response.Accepted);
        Assert.Equal(ActionResultCodes.ObjectIdInvalid, response.ResultCode);
    }

    [Fact]
    public async Task ExecuteQuarantineAsync_WhenExecutionIsNotImplemented_LeavesFileAndJournalPrepared()
    {
        // Arrange
        await _journal.InitializeAsync();

        var tempFile = CreateTempFile();
        var hash = await ComputeFileHashAsync(tempFile);

        var request = new ActionRequest(
            SchemaVersion: 1,
            RequestId: Guid.NewGuid(),
            ActionKind: ActionKinds.QuarantineFile,
            ObjectId: "obj-0123456789abcdef0123456789abcdef",
            PolicyVersion: DefaultActionCatalog.CurrentPolicyVersion,
            DryRun: false,
            UserSid: null,
            RequestedAtUtc: DateTimeOffset.UtcNow,
            Parameters: new Dictionary<string, string>
            {
                { "sourcePath", tempFile },
                { "expectedHash", hash }
            });

        try
        {
            var prepareResponse = await _manager.PrepareQuarantineAsync(request);
            var operationId = Guid.Parse(prepareResponse.OperationId!);

            // Act
            var executeResponse = await _manager.ExecuteQuarantineAsync(operationId, tempFile);

            // Assert
            Assert.False(executeResponse.Accepted);
            Assert.Equal(ActionResultCodes.RejectedNotImplemented, executeResponse.ResultCode);
            Assert.True(File.Exists(tempFile));

            // No execution transition may claim the file was quarantined.
            var operation = await _journal.GetPendingRecoveryAsync(limit: 1);
            var pending = Assert.Single(operation);
            Assert.Equal(JournalOperationState.Prepared, pending.State);
        }
        finally
        {
            DeleteTempFile(tempFile);
        }
    }

}
