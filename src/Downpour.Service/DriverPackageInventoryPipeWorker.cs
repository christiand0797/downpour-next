using System.Buffers.Binary;
using System.IO.Pipes;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

public sealed class DriverPackageInventoryPipeWorker(
    DriverPackageInventoryProvider provider,
    ILogger<DriverPackageInventoryPipeWorker> logger,
    string pipeName = DriverPackageInventoryClient.PipeName) : BackgroundService
{
    // Catalog verification of every package takes seconds; reuse a recent capture across quick refreshes.
    private readonly SnapshotCache<DriverPackageInventorySnapshot> _cache = new(provider.Capture, TimeSpan.FromSeconds(30), logger);

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

                var snapshot = await _cache.GetAsync(stoppingToken);

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
                logger.LogDebug(exception, "A local driver package inventory client disconnected before its response completed.");
            }
        }
    }
}
