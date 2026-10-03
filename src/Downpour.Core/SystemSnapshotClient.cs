using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed class SystemSnapshotClient
{
    public const string PipeName = "Downpour.SystemSnapshot.v1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<SystemHealthSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            return await JsonSerializer.DeserializeAsync<SystemHealthSnapshot>(pipe, JsonOptions, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
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
