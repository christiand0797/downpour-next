using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Client for the Process Termination action endpoint (DN-008 Phase 2).
/// Connects to the local service's action pipe to request operator preview and confirmed termination.
/// </summary>
public sealed class ProcessTerminationClient(string pipeName = ProcessTerminationClient.PipeName)
{
    public const string PipeName = "Downpour.ProcessTerminationActions.v1";
    private const int MaximumResponseBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 6,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public Task<ProcessTerminationResponse?> PreviewTerminateAsync(
        int processId,
        DateTimeOffset startTimeUtc,
        string? alertId = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new ProcessTerminationRequest(
            1,
            Guid.NewGuid(),
            ProcessTerminationOperations.Preview,
            processId,
            startTimeUtc,
            alertId),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<ProcessTerminationResponse?> TerminateAsync(
        int processId,
        DateTimeOffset startTimeUtc,
        string consentToken,
        string? alertId = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new ProcessTerminationRequest(
            1,
            Guid.NewGuid(),
            ProcessTerminationOperations.Terminate,
            processId,
            startTimeUtc,
            alertId,
            consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    private async Task<ProcessTerminationResponse?> SendAsync(
        ProcessTerminationRequest request,
        TimeSpan deadline,
        CancellationToken cancellationToken)
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
            var response = JsonSerializer.Deserialize<ProcessTerminationResponse>(buffer.ToArray(), Json);
            return response is { SchemaVersion: 1 } && response.RequestId == request.RequestId ? response : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or TimeoutException) { return null; }
    }
}
