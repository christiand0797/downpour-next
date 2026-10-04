using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>Accepts only local alert triage state changes. It exposes no operating-system actions.</summary>
public sealed class SecurityAlertControlPipeWorker(
    SecurityAlertRepository repository,
    SecurityAlertSnapshotStore store,
    ILogger<SecurityAlertControlPipeWorker> logger,
    string pipeName = SecurityAlertClient.PipeName + ".Control") : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 4 };
    private const int MaximumRequestBytes = 1024;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 2,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.WriteThrough, 1024, 1024,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                await pipe.WaitForConnectionAsync(timeout.Token);
                var request = await ReadRequestAsync(pipe, timeout.Token);
                var response = request is null
                    ? new AlertStateChangeResponse(1, Guid.Empty, false, "invalid-request")
                    : await repository.ChangeStateAsync(request, timeout.Token);
                if (response.Accepted)
                {
                    var refreshed = await repository.ReadSnapshotAsync(timeout.Token);
                    store.Publish(refreshed with { Warnings = store.Current.Warnings });
                }
                await JsonSerializer.SerializeAsync(pipe, response, JsonOptions, stoppingToken);
                await pipe.WriteAsync(new byte[] { (byte)'\n' }, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A local alert triage client disconnected before completion.");
            }
            catch (Exception exception) when (exception is not OperationCanceledException && !stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "The bounded local alert triage request failed.");
            }
        }
    }

    private static async Task<AlertStateChangeRequest?> ReadRequestAsync(Stream pipe, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[256];
        while (buffer.Length <= MaximumRequestBytes)
        {
            var read = await pipe.ReadAsync(chunk, token);
            if (read == 0) return null;
            var newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
            if (newline >= 0)
            {
                if (newline != read - 1 || buffer.Length + newline > MaximumRequestBytes) return null;
                await buffer.WriteAsync(chunk.AsMemory(0, newline), token);
                return ParseStrictRequest(buffer.ToArray());
            }
            if (buffer.Length + read > MaximumRequestBytes) return null;
            await buffer.WriteAsync(chunk.AsMemory(0, read), token);
        }
        return null;
    }

    internal static AlertStateChangeRequest? ParseStrictRequest(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumRequestBytes) return null;
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!values.TryAdd(property.Name, property.Value)) return null;
            if (values.Count != 5 || !values.TryGetValue("schemaVersion", out var schema) || !schema.TryGetInt32(out var version) ||
                !values.TryGetValue("requestId", out var requestId) || requestId.ValueKind != JsonValueKind.String ||
                !Guid.TryParseExact(requestId.GetString(), "D", out var parsedRequestId) ||
                !GetString(values, "alertId", out var alertId) || !GetString(values, "expectedState", out var expectedState) ||
                !GetString(values, "state", out var state)) return null;
            var result = new AlertStateChangeRequest(version, parsedRequestId, alertId, expectedState, state);
            return SecurityAlertClient.IsValidRequest(result) ? result : null;
        }
        catch (JsonException) { return null; }
    }

    private static bool GetString(IReadOnlyDictionary<string, JsonElement> values, string key, out string result)
    {
        result = "";
        if (!values.TryGetValue(key, out var value) || value.ValueKind != JsonValueKind.String) return false;
        result = value.GetString() ?? "";
        return result.Length <= 128 && !result.Any(char.IsControl);
    }
}
