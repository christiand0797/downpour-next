using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed class SensorSettingsClient(string pipeName = SensorSettingsClient.PipeName)
{
    public const string PipeName = "Downpour.SensorSettings.v1";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 4 };

    public Task<SensorSettingResponse?> GetAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.Get, false), cancellationToken);

    public Task<SensorSettingResponse?> SetAsync(string key, bool value, CancellationToken cancellationToken = default) =>
        SensorSettingKeys.Writable.Contains(key)
            ? SendAsync(new SensorSettingRequest(1, Guid.NewGuid(), key, value), cancellationToken)
            : Task.FromResult<SensorSettingResponse?>(null);

    private async Task<SensorSettingResponse?> SendAsync(SensorSettingRequest request, CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(request, Json), timeout.Token);
            await pipe.WriteAsync(new byte[] { (byte)'\n' }, timeout.Token);
            await pipe.FlushAsync(timeout.Token);

            using var buffer = new MemoryStream();
            var one = new byte[1];
            while (buffer.Length <= 1024)
            {
                if (await pipe.ReadAsync(one, timeout.Token) == 0) return null;
                if (one[0] == (byte)'\n') break;
                buffer.WriteByte(one[0]);
            }
            var response = JsonSerializer.Deserialize<SensorSettingResponse>(buffer.ToArray(), Json);
            return response is { SchemaVersion: 1 } && response.RequestId == request.RequestId ? response : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or TimeoutException) { return null; }
    }
}
