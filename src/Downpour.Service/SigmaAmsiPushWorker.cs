using System.Threading.Channels;
using Downpour.Contracts;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>Processes Sigma/AMSI matches from live event subscriptions and feeds alerts into the alert repository.</summary>
public sealed class SigmaAmsiPushWorker(
    SecurityEventProvider provider,
    SecurityAlertRepository alerts,
    SecurityAlertSnapshotStore alertSnapshots,
    ILogger<SigmaAmsiPushWorker> logger,
    ILogger<SigmaAmsiEventProcessor> processorLogger) : BackgroundService
{
    private const int QueueCapacity = 256;
    private const int MaximumBatchSize = 64;
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromMilliseconds(150);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = Channel.CreateBounded<SecurityEventObservation>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });

        var processor = new SigmaAmsiEventProcessor(processorLogger);

        using var subscriptions = provider.SubscribePush(
            observation =>
            {
                // Only queue PowerShell 4104 events for Sigma/AMSI processing
                if (observation.LogName.Equals("Microsoft-Windows-PowerShell/Operational", StringComparison.OrdinalIgnoreCase) &&
                    observation.EventId == 4104)
                {
                    if (!channel.Writer.TryWrite(observation))
                    {
                        logger.LogWarning("Sigma/AMSI event queue full; dropping event.");
                    }
                }
            },
            warning => logger.LogWarning(warning),
            out var activeSources);

        logger.LogInformation("Sigma/AMSI live event subscriptions active for PowerShell 4104 events; {ActiveSources} sources subscribed.", activeSources);

        try
        {
            await alerts.InitializeAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Sigma/AMSI push worker started, but persistent alert storage is not ready; processing will continue without persistence.");
        }

        try
        {
            while (await channel.Reader.WaitToReadAsync(stoppingToken))
            {
                await Task.Delay(CoalesceWindow, stoppingToken);

                var batch = new List<SecurityEventObservation>(MaximumBatchSize);
                while (batch.Count < MaximumBatchSize && channel.Reader.TryRead(out var observation))
                    batch.Add(observation);

                if (batch.Count == 0) continue;

                try
                {
                    var observations = new List<SecurityEventObservation>();
                    foreach (var observation in batch)
                    {
                        var generatedAlerts = processor.ProcessEvent(observation);
                        foreach (var alert in generatedAlerts)
                        {
                            observations.Add(new SecurityEventObservation(
                                alert.LogName, alert.Provider, alert.EventId, alert.RecordId, alert.EventTimeUtc,
                                alert.Severity, alert.Technique, alert.Title, alert.Occurrences));
                        }
                    }

                    if (observations.Count > 0)
                    {
                        var snapshot = new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, observations, 1, []);
                        await alerts.IngestAsync(snapshot, stoppingToken);

                        // Publish updated alert snapshot
                        var alertSnapshot = await alerts.ReadSnapshotAsync(stoppingToken);
                        alertSnapshots.Publish(alertSnapshot);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "Sigma/AMSI event processing failed; alerts may not be persisted.");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}