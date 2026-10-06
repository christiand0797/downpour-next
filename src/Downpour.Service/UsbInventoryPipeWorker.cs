using System.Buffers.Binary;
using System.IO.Pipes;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

public sealed class UsbInventoryPipeWorker(
    UsbInventoryProvider provider,
    ILogger<UsbInventoryPipeWorker> logger,
    string pipeName = UsbInventoryClient.PipeName) : BackgroundService
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(15);
    private UsbSnapshot? _cached;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
                    PipeDirection.Out,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    inBufferSize: 0,
                    outBufferSize: 4096,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());

                using var connectionTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                connectionTimeout.CancelAfter(TimeSpan.FromSeconds(5));
                await pipe.WaitForConnectionAsync(connectionTimeout.Token);

                var snapshot = _cached;
                if (snapshot is null || DateTimeOffset.UtcNow - snapshot.CapturedAtUtc > CacheLifetime)
                    _cached = snapshot = await Task.Run(provider.Capture, stoppingToken);

                var payload = BoundedJson.Serialize(snapshot);
                var lengthBytes = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, payload.Length);
                await pipe.WriteAsync(lengthBytes, stoppingToken);
                await pipe.WriteAsync(payload, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
            {
                // Recreate the endpoint after an idle client timeout.
            }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A local USB inventory client disconnected before its response completed.");
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(exception, "Unexpected error in USB inventory pipe worker.");
                await Task.Delay(500, stoppingToken);
            }
        }
    }
}
