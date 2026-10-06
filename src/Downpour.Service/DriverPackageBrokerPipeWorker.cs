using System.Threading.Channels;
using Downpour.Contracts;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>Handles driver package action requests from the desktop via bounded IPC.</summary>
public sealed class DriverPackageBrokerPipeWorker(
    DriverPackageBroker driverPackageBroker,
    ILogger<DriverPackageBrokerPipeWorker> logger) : BackgroundService
{
    private const int QueueCapacity = 64;
    private const int MaximumBatchSize = 16;
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromMilliseconds(200);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = Channel.CreateBounded<DriverPackageRequest>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });

        logger.LogInformation("Driver package broker pipe worker started (prepared intent only; execution not implemented).");

        try
        {
            while (await channel.Reader.WaitToReadAsync(stoppingToken))
            {
                await Task.Delay(CoalesceWindow, stoppingToken);

                var batch = new List<DriverPackageRequest>(MaximumBatchSize);
                while (batch.Count < MaximumBatchSize && channel.Reader.TryRead(out var request))
                    batch.Add(request);

                if (batch.Count == 0) continue;

                foreach (var request in batch)
                {
                    try
                    {
                        // Currently only prepare is implemented; execution is rejected
                        var response = await driverPackageBroker.PrepareAsync(request, stoppingToken);
                        logger.LogInformation("Driver package broker: {ActionKind} prepared for {RequestId} -> {ResultCode}", request.ActionKind, request.RequestId, response.ResultCode);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                    catch (Exception exception)
                    {
                        logger.LogError(exception, "Driver package broker: error processing request {RequestId}", request.RequestId);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}