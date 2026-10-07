using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Client for the Firewall Action endpoint (DN-008 Phase 3).
/// Connects to the local service's action pipe to request operator preview and confirmed execution
/// of remote IP blocks and Downpour firewall rule removals.
/// </summary>
public sealed class FirewallActionClient(string pipeName = FirewallActionClient.PipeName)
{
    public const string PipeName = "Downpour.FirewallActions.v1";
    private const int MaximumResponseBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public Task<FirewallActionResponse?> PreviewBlockIpAsync(
        string targetIp,
        int durationMinutes = 1440,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.PreviewBlockIp,
            TargetIp: targetIp,
            DurationMinutes: durationMinutes,
            Reason: reason),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<FirewallActionResponse?> BlockIpAsync(
        string targetIp,
        string consentToken,
        int durationMinutes = 1440,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.BlockIp,
            TargetIp: targetIp,
            DurationMinutes: durationMinutes,
            Reason: reason,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    public Task<FirewallActionResponse?> PreviewRemoveRuleAsync(
        string ruleName,
        CancellationToken cancellationToken = default) =>
        SendAsync(new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.PreviewRemoveRule,
            RuleName: ruleName),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<FirewallActionResponse?> RemoveRuleAsync(
        string ruleName,
        string consentToken,
        CancellationToken cancellationToken = default) =>
        SendAsync(new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.RemoveRule,
            RuleName: ruleName,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    public Task<FirewallActionResponse?> PreviewCleanupLegacyAsync(
        CancellationToken cancellationToken = default) =>
        SendAsync(new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.PreviewCleanupLegacy),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<FirewallActionResponse?> CleanupLegacyAsync(
        string consentToken,
        CancellationToken cancellationToken = default) =>
        SendAsync(new FirewallActionRequest(
            1,
            Guid.NewGuid(),
            FirewallActionOperations.CleanupLegacy,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(30),
            cancellationToken);

    private async Task<FirewallActionResponse?> SendAsync(
        FirewallActionRequest request,
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
            var response = JsonSerializer.Deserialize<FirewallActionResponse>(buffer.ToArray(), Json);
            return response is { SchemaVersion: 1 } && response.RequestId == request.RequestId ? response : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or TimeoutException) { return null; }
    }
}
