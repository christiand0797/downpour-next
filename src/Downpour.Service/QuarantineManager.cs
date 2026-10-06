using Downpour.Contracts;
using System.Security.Cryptography;

namespace Downpour.Service;

/// <summary>
/// Prepares quarantine requests for review and records intent in the operation journal.
/// File mutation is deliberately not implemented.
/// </summary>
public sealed class QuarantineManager
{
    private const int MaxFileSizeBytes = 256 * 1024 * 1024; // 256 MiB
    private const int MaxPathLength = 260;
    private readonly OperationJournal _journal;
    private readonly ILogger<QuarantineManager> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public QuarantineManager(OperationJournal journal, ILogger<QuarantineManager> logger)
    {
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Prepares a quarantine operation: validates the file, computes its hash, and records intent in the journal.
    /// This does not move the file yet; the user must consent before execution.
    /// </summary>
    public async Task<ActionResponse> PrepareQuarantineAsync(
        ActionRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (request.ActionKind != ActionKinds.QuarantineFile)
            throw new ArgumentException("Invalid action kind for quarantine.", nameof(request));

        if (!request.Parameters.TryGetValue("sourcePath", out var sourcePath) || sourcePath == null ||
            !request.Parameters.TryGetValue("expectedHash", out var expectedHash) || expectedHash == null)
        {
            return new ActionResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: false,
                ResultCode: ActionResultCodes.ParameterInvalid,
                OperationId: null,
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string> { { "error", "Missing required parameters: sourcePath, expectedHash" } },
                Warnings: Array.Empty<string>());
        }

        // Validate source path
        if (!IsValidPath(sourcePath, out var pathError))
        {
            return new ActionResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: false,
                ResultCode: ActionResultCodes.ObjectIdInvalid,
                OperationId: null,
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string> { { "error", pathError ?? "Invalid source path" } },
                Warnings: Array.Empty<string>());
        }

        // Check if file exists and is accessible
        if (!File.Exists(sourcePath))
        {
            return new ActionResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: false,
                ResultCode: ActionResultCodes.ObjectIdInvalid,
                OperationId: null,
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string> { { "error", "Source file does not exist or is inaccessible" } },
                Warnings: Array.Empty<string>());
        }

        // Check file size
        var fileInfo = new FileInfo(sourcePath);
        if (fileInfo.Length > MaxFileSizeBytes)
        {
            return new ActionResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: false,
                ResultCode: ActionResultCodes.ParameterInvalid,
                OperationId: null,
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string> { { "error", $"File size {fileInfo.Length} exceeds maximum {MaxFileSizeBytes}" } },
                Warnings: Array.Empty<string>());
        }

        // Compute actual hash
        string actualHash;
        try
        {
            actualHash = await ComputeFileHashAsync(sourcePath, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to compute hash for file: {Path}", sourcePath);
            return new ActionResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: false,
                ResultCode: ActionResultCodes.ExecutionFailed,
                OperationId: null,
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string> { { "error", $"Hash computation failed: {ex.Message}" } },
                Warnings: Array.Empty<string>());
        }

        // Verify hash matches expected
        if (!string.Equals(actualHash, expectedHash ?? "null", StringComparison.OrdinalIgnoreCase))
        {
            return new ActionResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: false,
                ResultCode: ActionResultCodes.ParameterInvalid,
                OperationId: null,
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string>
                {
                    { "error", "Hash mismatch" },
                    { "expected", expectedHash ?? "null" },
                    { "actual", actualHash }
                },
                Warnings: Array.Empty<string>());
        }

        // Record intent in journal
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var operationId = Guid.NewGuid();
            var eventId = Guid.NewGuid();

            var operation = await _journal.BeginAsync(
                operationId,
                JournalOperationKind.QuarantineFile,
                request.PolicyVersion,
                request.ObjectId,
                eventId,
                cancellationToken);

            _logger.LogInformation(
                "Quarantine prepared: OperationId={OperationId}, Path={Path}, Hash={Hash}",
                operationId, sourcePath, actualHash);

            return new ActionResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: true,
                ResultCode: ActionResultCodes.Accepted,
                OperationId: operationId.ToString("D"),
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string>
                {
                    { "operationId", operationId.ToString("D") },
                    { "computedHash", actualHash },
                    { "fileSize", fileInfo.Length.ToString() }
                },
                Warnings: Array.Empty<string>());
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Rejects execution while file mutation is unimplemented. Prepared journal entries remain pending.
    /// </summary>
    public async Task<ActionResponse> ExecuteQuarantineAsync(
        Guid operationId,
        string sourcePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _logger.LogWarning("Quarantine execution rejected because mutation is not implemented: OperationId={OperationId}", operationId);
        return await Task.FromResult(new ActionResponse(
            SchemaVersion: 1,
            RequestId: Guid.Empty,
            Accepted: false,
            ResultCode: ActionResultCodes.RejectedNotImplemented,
            OperationId: operationId.ToString("D"),
            RespondedAtUtc: DateTimeOffset.UtcNow,
            Details: new Dictionary<string, string>
            {
                { "status", "execution-not-implemented" }
            },
            Warnings: new[] { "No quarantine file mutation was performed" }));
    }

    private static bool IsValidPath(string path, out string? error)
    {
        error = null;

        if (string.IsNullOrWhiteSpace(path))
        {
            error = "Path is empty";
            return false;
        }

        if (path.Length > MaxPathLength)
        {
            error = $"Path exceeds maximum length of {MaxPathLength}";
            return false;
        }

        // Check for suspicious patterns
        if (path.Contains("..", StringComparison.Ordinal))
        {
            error = "Path contains directory traversal";
            return false;
        }

        // Ensure path is absolute
        if (!Path.IsPathRooted(path))
        {
            error = "Path must be absolute";
            return false;
        }

        // Check for reserved device names
        var fileName = Path.GetFileName(path);
        var reservedNames = new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
        var fileNameWithoutExt = Path.GetFileNameWithoutExtension(fileName).ToUpperInvariant();
        if (reservedNames.Contains(fileNameWithoutExt))
        {
            error = "Path contains a reserved device name";
            return false;
        }

        return true;
    }

    private static async Task<string> ComputeFileHashAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        using var sha256 = SHA256.Create();
        var hashBytes = await Task.Run(() => sha256.ComputeHash(stream), cancellationToken);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}
