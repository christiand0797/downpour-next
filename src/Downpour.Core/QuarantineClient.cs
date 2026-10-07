using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Desktop side of the quarantine action pipe. Returns null when the service is unreachable or replies invalidly.</summary>
public sealed class QuarantineClient(string pipeName = QuarantineClient.PipeName)
{
    public const string PipeName = "Downpour.QuarantineActions.v1";
    private const int MaximumResponseBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 6,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public Task<QuarantineResponse?> ListAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), QuarantineOperations.List), TimeSpan.FromSeconds(5), cancellationToken);

    public Task<QuarantineResponse?> PreviewQuarantineAsync(string path, CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), QuarantineOperations.PreviewQuarantine, Path: path), TimeSpan.FromMinutes(2), cancellationToken);

    /// <summary><paramref name="reviewedPath"/> is the target path shown in the preview (the service's resolved path).</summary>
    public Task<QuarantineResponse?> QuarantineAsync(string reviewedPath, string consentToken, CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), QuarantineOperations.Quarantine, Path: reviewedPath, ConsentToken: consentToken), TimeSpan.FromMinutes(5), cancellationToken);

    public Task<QuarantineResponse?> PreviewRestoreAsync(string objectId, string? restorePath, CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), QuarantineOperations.PreviewRestore, ObjectId: objectId, RestorePath: restorePath), TimeSpan.FromSeconds(10), cancellationToken);

    public Task<QuarantineResponse?> RestoreAsync(string objectId, string? restorePath, string consentToken, CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), QuarantineOperations.Restore, ObjectId: objectId, RestorePath: restorePath, ConsentToken: consentToken), TimeSpan.FromMinutes(5), cancellationToken);

    private async Task<QuarantineResponse?> SendAsync(QuarantineRequest request, TimeSpan deadline, CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(deadline);
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(request, Json), timeout.Token);
            await pipe.WriteAsync(new byte[] { (byte)'\n' }, timeout.Token);
            await pipe.FlushAsync(timeout.Token);

            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            while (buffer.Length <= MaximumResponseBytes)
            {
                var read = await pipe.ReadAsync(chunk, timeout.Token);
                if (read == 0) return null;
                var newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
                buffer.Write(chunk, 0, newline >= 0 ? newline : read);
                if (newline >= 0) break;
            }
            if (buffer.Length > MaximumResponseBytes) return null;
            var response = JsonSerializer.Deserialize<QuarantineResponse>(buffer.ToArray(), Json);
            return response is { SchemaVersion: 1 } && response.RequestId == request.RequestId ? response : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or TimeoutException) { return null; }
    }
}
