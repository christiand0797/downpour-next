using System.Text;
using System.Threading.Channels;
using Downpour.Contracts;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>Processes Sysmon event matches from live event subscriptions and feeds alerts into the alert repository.</summary>
public sealed class SysmonPushWorker(
    SysmonProvider provider,
    SecurityAlertRepository alerts,
    SecurityAlertSnapshotStore alertSnapshots,
    ILogger<SysmonPushWorker> logger) : BackgroundService
{
    private const int QueueCapacity = 256;
    private const int MaximumBatchSize = 64;
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromMilliseconds(150);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = Channel.CreateBounded<SysmonObservation>(new BoundedChannelOptions(QueueCapacity)
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
                    logger.LogWarning("Sysmon event queue full; dropping event.");
                }
            },
            warning => logger.LogWarning(warning),
            out var activeSources);

        logger.LogInformation("Sysmon live event subscriptions active for {ActiveSources} sources subscribed.", activeSources);

        try
        {
            await alerts.InitializeAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Sysmon push worker started, but persistent alert storage is not ready; processing will continue without persistence.");
        }

        try
        {
            while (await channel.Reader.WaitToReadAsync(stoppingToken))
            {
                await Task.Delay(CoalesceWindow, stoppingToken);

                var batch = new List<SysmonObservation>(MaximumBatchSize);
                while (batch.Count < MaximumBatchSize && channel.Reader.TryRead(out var observation))
                    batch.Add(observation);

                if (batch.Count == 0) continue;

                try
                {
                    var observations = new List<SecurityEventObservation>(batch.Count);
                    foreach (var observation in batch)
                    {
                        if (SysmonCatalog.TryGetRule(observation.LogName, observation.EventId, out var rule))
                        {
                            var alertId = ComputeAlertId("sysmon", observation.RecordId?.ToString() ?? "unknown", observation.RecordId ?? 0);
                            observations.Add(new SecurityEventObservation(
                                observation.LogName, observation.Provider, observation.EventId, observation.RecordId,
                                observation.CreatedAtUtc ?? DateTimeOffset.UtcNow, rule.Severity, rule.Technique, rule.Summary, observation.Occurrences));
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
                    logger.LogWarning(exception, "Sysmon event processing failed; alerts may not be persisted.");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private static string ComputeAlertId(string prefix, string identifier, long recordId)
    {
        var input = $"{prefix}-{identifier}-{recordId}";
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash);
    }
}