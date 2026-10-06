using System.Threading.Channels;
using Downpour.Contracts;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>Handles action requests from the desktop via bounded IPC.</summary>
public sealed class ActionBrokerPipeWorker(
    QuarantineManager quarantineManager,
    ILogger<ActionBrokerPipeWorker> logger) : BackgroundService
{
    private const int QueueCapacity = 64;
    private const int MaximumBatchSize = 16;
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromMilliseconds(200);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = Channel.CreateBounded<ActionRequest>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });

        logger.LogInformation("Action broker pipe worker started (prepared intent only; execution not implemented).");

        try
        {
            while (await channel.Reader.WaitToReadAsync(stoppingToken))
            {
                await Task.Delay(CoalesceWindow, stoppingToken);

                var batch = new List<ActionRequest>(MaximumBatchSize);
                while (batch.Count < MaximumBatchSize && channel.Reader.TryRead(out var request))
                    batch.Add(request);

                if (batch.Count == 0) continue;

                foreach (var request in batch)
                {
                    try
                    {
                        // Currently only prepare quarantine is implemented; execution is rejected
                        if (request.ActionKind == ActionKinds.QuarantineFile)
                        {
                            var response = await quarantineManager.PrepareQuarantineAsync(request, stoppingToken);
                            logger.LogInformation("Action broker: quarantine prepared for {RequestId} -> {ResultCode}", request.RequestId, response.ResultCode);
                        }
                        else
                        {
                            logger.LogWarning("Action broker: unsupported action kind {ActionKind} for {RequestId}", request.ActionKind, request.RequestId);
                        }
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                    catch (Exception exception)
                    {
                        logger.LogError(exception, "Action broker: error processing request {RequestId}", request.RequestId);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}