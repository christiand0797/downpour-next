using Downpour.Contracts;
using System.IO.Pipes;
using System.Text.Json;
using Downpour.Core;

namespace Downpour.Service;

public sealed class SnapshotPipeWorker(
    SystemSnapshotProvider provider,
    ILogger<SnapshotPipeWorker> logger,
    string pipeName = SystemSnapshotClient.PipeName) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SnapshotCache<SystemHealthSnapshot> _cache = new(provider.Capture, TimeSpan.FromSeconds(1), logger);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _cache.Warm();
        logger.LogInformation("Downpour sensor service started. Connected sensors: read-only process, CPU, memory, and TCP summary.");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
                    PipeDirection.Out,
                    maxNumberOfServerInstances: 4,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    inBufferSize: 0,
                    outBufferSize: 4096,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());

                using var connectionTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                connectionTimeout.CancelAfter(TimeSpan.FromSeconds(5));
                await pipe.WaitForConnectionAsync(connectionTimeout.Token);
                var snapshot = await _cache.GetAsync(stoppingToken);
                await JsonSerializer.SerializeAsync(pipe, snapshot, JsonOptions, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
            {
                // Recreate the pipe after idle time so every client receives a fresh, bounded connection.
            }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A local snapshot client disconnected before its response completed.");
            }
        }
    }

}
