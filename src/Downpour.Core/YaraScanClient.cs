using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Desktop side of the read-only YARA scan pipe. Returns null when the service is unreachable or replies invalidly.</summary>
public sealed class YaraScanClient(string pipeName = YaraScanClient.PipeName)
{
    public const string PipeName = "Downpour.YaraScan.v1";
    private const int MaximumResponseBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 16,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public Task<YaraScanResponse?> StatusAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), YaraScanOperations.Status), cancellationToken);

    public Task<YaraScanResponse?> StartAsync(string path, bool recursive, CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), YaraScanOperations.Start, path, recursive), cancellationToken);

    public Task<YaraScanResponse?> CancelAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new(1, Guid.NewGuid(), YaraScanOperations.Cancel), cancellationToken);

    private async Task<YaraScanResponse?> SendAsync(YaraScanRequest request, CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(request, Json), timeout.Token);
            await pipe.WriteAsync(new byte[] { (byte)'\n' }, timeout.Token);
            await pipe.FlushAsync(timeout.Token);

            using var buffer = new MemoryStream();
            var chunk = new byte[16384];
            while (buffer.Length <= MaximumResponseBytes)
            {
                var read = await pipe.ReadAsync(chunk, timeout.Token);
                if (read == 0) return null;
                var newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
                buffer.Write(chunk, 0, newline >= 0 ? newline : read);
                if (newline >= 0) break;
            }
            if (buffer.Length > MaximumResponseBytes) return null;
            var response = JsonSerializer.Deserialize<YaraScanResponse>(buffer.ToArray(), Json);
            return response is { SchemaVersion: 1 } && response.RequestId == request.RequestId ? response : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or TimeoutException) { return null; }
    }
}
