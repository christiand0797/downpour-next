using System.Threading.Channels;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Handles fixed-catalog event subscriptions with a bounded metadata-only queue; polling remains the fallback.</summary>
public sealed class SecurityEventPushWorker(
    SecurityEventProvider provider,
    SecurityEventSnapshotStore eventSnapshots,
    SecurityEventPushStatus pushStatus,
    SecurityAlertRepository alerts,
    SecurityAlertSnapshotStore alertSnapshots,
    ILogger<SecurityEventPushWorker> logger) : BackgroundService
{
    private const int QueueCapacity = 512;
    private const int MaximumBatchSize = 256;
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
        using var subscriptions = provider.SubscribePush(
            observation =>
            {
                if (!channel.Writer.TryWrite(observation))
                {
                    pushStatus.RecordDroppedEvent();
                }
            },
            pushStatus.ReportWarning,
            out var activeSources);
        logger.LogInformation("Live Windows event subscriptions active for {ActiveSources} of 7 channels; bounded polling remains the fallback.", activeSources);

        try
        {
            await alerts.InitializeAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Live event subscriptions started, but the persistent alert store is not ready; polling remains active.");
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

                var merged = SecurityEventPushBatch.Merge(eventSnapshots.Current, batch, DateTimeOffset.UtcNow, pushStatus.GetWarnings());
                eventSnapshots.Publish(merged);

                try
                {
                    await alerts.IngestAsync(merged, stoppingToken);
                    var alertSnapshot = await alerts.ReadSnapshotAsync(stoppingToken);
                    var alertWarnings = merged.Warnings.ToList();
                    if (merged.SourcesQueried < 7)
                        alertWarnings.Add($"Only {merged.SourcesQueried} of 7 allow-listed event channels were readable during the latest refresh.");
                    alertSnapshots.Publish(alertSnapshot with { Warnings = alertWarnings.Distinct(StringComparer.Ordinal).Take(32).ToArray() });
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "Live event metadata was captured but could not be persisted; periodic polling remains active.");
                    PublishPersistenceWarning(merged.Warnings);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private void PublishPersistenceWarning(IReadOnlyList<string> sourceWarnings)
    {
        try
        {
            var current = alertSnapshots.Current;
            var warnings = sourceWarnings.Append("Live event metadata could not be persisted; alert storage will be retried.")
                .Distinct(StringComparer.Ordinal).Take(32).ToArray();
            alertSnapshots.Publish(current with { CapturedAtUtc = DateTimeOffset.UtcNow, Warnings = warnings });
        }
        catch (Exception exception)
        {
            logger.LogDebug(exception, "Could not publish a live-event persistence warning.");
        }
    }
}
