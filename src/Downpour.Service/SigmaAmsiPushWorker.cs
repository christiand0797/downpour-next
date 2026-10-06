using System.Threading.Channels;
using Downpour.Contracts;
using Downpour.Core;
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
                    // Detections are stored as findings. Converting them back into event observations failed the
                    // fixed event-catalog validation (4104 = "PowerShell script block recorded", LOW), so every
                    // Sigma/AMSI detection used to be dropped with only a log warning.
                    var findings = batch
                        .SelectMany(processor.ProcessEvent)
                        .Select(ToFinding)
                        .Take(SecurityAlertRepository.MaximumFindingsPerIngest)
                        .ToArray();

                    if (findings.Length > 0)
                    {
                        await alerts.IngestFindingsAsync(findings, DateTimeOffset.UtcNow, stoppingToken);

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

    /// <summary>Maps a processor detection to a finding; the processor's alert ID (rule + event record) is the identity.</summary>
    internal static SecurityFindingObservation ToFinding(SecurityAlert detection)
    {
        var amsi = detection.Title.StartsWith("AMSI", StringComparison.Ordinal);
        return SecurityFindingMapper.Create(
            amsi ? SecurityFindingCatalog.Amsi : SecurityFindingCatalog.Sigma,
            amsi ? "AMSI" : "Sigma rule",
            SecurityFindingCatalog.Severities.Contains(detection.Severity) ? detection.Severity : "MEDIUM",
            detection.Technique,
            detection.Title,
            detection.AlertId.ToLowerInvariant());
    }
}
