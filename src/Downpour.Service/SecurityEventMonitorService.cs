using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Continuously refreshes local Windows event metadata independently of the visible UI route.</summary>
public sealed class SecurityEventMonitorService(
    SecurityEventProvider provider,
    SecurityEventSnapshotStore store,
    ILogger<SecurityEventMonitorService> logger) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(PollInterval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var snapshot = await Task.Run(provider.Capture, stoppingToken);
                store.Publish(snapshot);
                logger.LogInformation("Windows event monitor refreshed: {EventCount} observations, {SourceCount} sources.",
                    snapshot.Events.Count, snapshot.SourcesQueried);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Windows event monitor refresh failed.");
                store.Publish(new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, [], 0,
                    ["Windows event monitoring is unavailable; see the local service log for details."]));
            }

            try
            {
                if (!await timer.WaitForNextTickAsync(stoppingToken)) break;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
