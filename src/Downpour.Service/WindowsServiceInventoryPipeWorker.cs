using Downpour.Contracts;
using System.IO.Pipes;
using System.Text.Json;
using Downpour.Core;

namespace Downpour.Service;

public sealed class WindowsServiceInventoryPipeWorker(
    WindowsServiceInventoryProvider provider,
    ILogger<WindowsServiceInventoryPipeWorker> logger,
    string pipeName = WindowsServiceInventoryClient.PipeName) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SnapshotCache<WindowsServiceInventorySnapshot> _cache = new(provider.Capture, TimeSpan.FromSeconds(3), logger);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
                    PipeDirection.Out,
                    maxNumberOfServerInstances: 2,
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
                // Recreate the endpoint after an idle client timeout.
            }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A local Windows service inventory client disconnected before its response completed.");
            }
        }
    }
}
