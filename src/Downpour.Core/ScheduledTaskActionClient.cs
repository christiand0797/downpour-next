using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Client for the scheduled-task action endpoint. Nothing mutates without a preview that mints a single-use
/// consent token, and the service re-checks the feature switch, path policy and caller identity on every request.
/// </summary>
public sealed class ScheduledTaskActionClient(string pipeName = ScheduledTaskActionClient.PipeName)
{
    public const string PipeName = "Downpour.ScheduledTaskActions.v1";
    private const int MaximumResponseBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public Task<ScheduledTaskActionResponse?> PreviewAsync(
        string taskPath,
        ScheduledTaskActionKind kind,
        CancellationToken cancellationToken = default) =>
        SendAsync(new ScheduledTaskActionRequest(1, Guid.NewGuid(), PreviewOperation(kind), TaskPath: taskPath),
            TimeSpan.FromSeconds(10), cancellationToken);

    public Task<ScheduledTaskActionResponse?> ExecuteAsync(
        string taskPath,
        ScheduledTaskActionKind kind,
        string consentToken,
        CancellationToken cancellationToken = default) =>
        SendAsync(new ScheduledTaskActionRequest(1, Guid.NewGuid(), ExecuteOperation(kind), TaskPath: taskPath,
            ConsentToken: consentToken), TimeSpan.FromSeconds(20), cancellationToken);

    internal static string PreviewOperation(ScheduledTaskActionKind kind) => kind switch
    {
        ScheduledTaskActionKind.Enable => ScheduledTaskActionOperations.PreviewEnable,
        ScheduledTaskActionKind.Disable => ScheduledTaskActionOperations.PreviewDisable,
        _ => ScheduledTaskActionOperations.PreviewDelete,
    };

    internal static string ExecuteOperation(ScheduledTaskActionKind kind) => kind switch
    {
        ScheduledTaskActionKind.Enable => ScheduledTaskActionOperations.Enable,
        ScheduledTaskActionKind.Disable => ScheduledTaskActionOperations.Disable,
        _ => ScheduledTaskActionOperations.Delete,
    };

    private async Task<ScheduledTaskActionResponse?> SendAsync(
        ScheduledTaskActionRequest request,
        TimeSpan deadline,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = new CancellationTokenSource(deadline);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, cancellationToken);
        try
        {
            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
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
            return JsonSerializer.Deserialize<ScheduledTaskActionResponse>(buffer.ToArray(), Json);
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
