using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Client for the Host Isolation Action endpoint (DN-008 Phase 5).
/// Connects to the local service's action pipe to request operator preview and confirmed execution
/// of emergency host isolation with an enforced auto-expiry guarantee.
/// </summary>
public sealed class HostIsolationClient(string pipeName = HostIsolationClient.PipeName)
{
    public const string PipeName = "Downpour.HostIsolation.v1";
    private const int MaximumResponseBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public Task<HostIsolationResponse?> GetStatusAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new HostIsolationRequest(
            1,
            Guid.NewGuid(),
            HostIsolationOperations.GetStatus),
            TimeSpan.FromSeconds(5),
            cancellationToken);

    public Task<HostIsolationResponse?> PreviewIsolateAsync(
        int durationMinutes = 30,
        bool lockWorkstation = false,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new HostIsolationRequest(
            1,
            Guid.NewGuid(),
            HostIsolationOperations.PreviewIsolate,
            DurationMinutes: durationMinutes,
            LockWorkstation: lockWorkstation,
            Reason: reason),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<HostIsolationResponse?> IsolateAsync(
        string consentToken,
        int durationMinutes = 30,
        bool lockWorkstation = false,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new HostIsolationRequest(
            1,
            Guid.NewGuid(),
            HostIsolationOperations.Isolate,
            DurationMinutes: durationMinutes,
            LockWorkstation: lockWorkstation,
            Reason: reason,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    public Task<HostIsolationResponse?> PreviewReleaseAsync(
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new HostIsolationRequest(
            1,
            Guid.NewGuid(),
            HostIsolationOperations.PreviewRelease,
            Reason: reason),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<HostIsolationResponse?> ReleaseAsync(
        string consentToken,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new HostIsolationRequest(
            1,
            Guid.NewGuid(),
            HostIsolationOperations.Release,
            Reason: reason,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    private async Task<HostIsolationResponse?> SendAsync(
        HostIsolationRequest request,
        TimeSpan deadline,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = new CancellationTokenSource(deadline);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, cancellationToken);

        try
        {
            using var client = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await client.ConnectAsync(linkedCts.Token);

            var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, Json);
            await client.WriteAsync(requestBytes, linkedCts.Token);
            client.WriteByte((byte)'\n');
            await client.FlushAsync(linkedCts.Token);

            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            while (buffer.Length <= MaximumResponseBytes)
            {
                var read = await client.ReadAsync(chunk, linkedCts.Token);
                if (read == 0) break;
                var newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
                if (newline >= 0)
                {
                    buffer.Write(chunk, 0, newline);
                    break;
                }
                buffer.Write(chunk, 0, read);
            }

            if (buffer.Length == 0) return null;
            return JsonSerializer.Deserialize<HostIsolationResponse>(buffer.ToArray(), Json);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
