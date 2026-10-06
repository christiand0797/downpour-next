using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>Reads or sets one allow-listed sensor setting. Newline-delimited JSON, 1 KiB cap, strict parsing, current-user ACL.</summary>
public sealed class SensorSettingsPipeWorker(
    SensorSettingsStore store,
    ILogger<SensorSettingsPipeWorker> logger,
    string pipeName = SensorSettingsClient.PipeName) : BackgroundService
{
    private const int MaximumRequestBytes = 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 4 };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.WriteThrough, 1024, 1024,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                await pipe.WaitForConnectionAsync(timeout.Token);
                var line = await ReadLineAsync(pipe, timeout.Token);
                var request = line is null ? null : ParseStrictRequest(line);
                var response = request is null
                    ? new SensorSettingResponse(1, Guid.Empty, false, "invalid-request", null)
                    : store.Apply(request);
                if (request is not null && response.ResultCode == "updated")
                    logger.LogInformation("Sensor setting {Key} set to {Value} by the local desktop.", request.Key, request.Value);
                await JsonSerializer.SerializeAsync(pipe, response, JsonOptions, stoppingToken);
                await pipe.WriteAsync(new byte[] { (byte)'\n' }, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A sensor settings client disconnected before completion.");
            }
        }
    }

    private static async Task<byte[]?> ReadLineAsync(Stream pipe, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        var one = new byte[1];
        while (buffer.Length <= MaximumRequestBytes)
        {
            if (await pipe.ReadAsync(one, token) == 0) return null;
            if (one[0] == (byte)'\n') return buffer.Length == 0 ? null : buffer.ToArray();
            buffer.WriteByte(one[0]);
        }
        return null;
    }

    /// <summary>Exactly four properties: schemaVersion, requestId (GUID "D"), key (allow-listed), value (boolean).</summary>
    internal static SensorSettingRequest? ParseStrictRequest(byte[] bytes)
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
            if (values.Count != 4
                || !values.TryGetValue("schemaVersion", out var schema) || !schema.TryGetInt32(out var version) || version != 1
                || !values.TryGetValue("requestId", out var id) || id.ValueKind != JsonValueKind.String || !Guid.TryParseExact(id.GetString(), "D", out var requestId)
                || !values.TryGetValue("key", out var key) || key.ValueKind != JsonValueKind.String
                || !values.TryGetValue("value", out var value) || value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                return null;
            var name = key.GetString() ?? "";
            if (name != SensorSettingKeys.Get && !SensorSettingKeys.Writable.Contains(name)) return null;
            return new SensorSettingRequest(version, requestId, name, value.GetBoolean());
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
