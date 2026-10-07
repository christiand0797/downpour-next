using System.Threading.Channels;
using Downpour.Contracts;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>Sysmon metadata push with bounded polling fallback and visible collection health.</summary>
public sealed class SysmonPushWorker(
    SysmonProvider provider,
    SysmonSnapshotStore snapshots,
    SecurityAlertRepository alerts,
    SecurityAlertSnapshotStore alertSnapshots,
    ILogger<SysmonPushWorker> logger) : BackgroundService
{
    private const int QueueCapacity = 256;
    private const int MaximumBatchSize = 64;
    private long _dropped;
    private bool _alertStoreReady;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = Channel.CreateBounded<SysmonObservation>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false,
            AllowSynchronousContinuations = false
        });
        using var subscriptions = provider.SubscribePush(
            observation => { if (!channel.Writer.TryWrite(observation)) Interlocked.Increment(ref _dropped); },
            warning =>
            {
                alertSnapshots.SetSourceWarnings("Sysmon live", [warning]);
                logger.LogWarning("{Warning}", warning);
            }, out var activeSources);
        logger.LogInformation("Sysmon live subscription active for {ActiveSources} channel; polling runs every 15 seconds.", activeSources);
        try
        {
            try
            {
                await alerts.InitializeAsync(stoppingToken);
                _alertStoreReady = true;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                alertSnapshots.SetSourceWarnings("Sysmon persistence", ["Sysmon alert storage is unavailable; collection continues and storage will be retried."]);
                logger.LogWarning(exception, "Sysmon worker could not initialize alert storage.");
            }
            await Task.WhenAll(PollAsync(stoppingToken), PushAsync(channel.Reader, stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private async Task PollAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        do
        {
            token.ThrowIfCancellationRequested();
            try
            {
                var snapshot = provider.Capture();
                snapshots.Publish(snapshot);
                var warnings = snapshot.Warnings.ToList();
                if (snapshot.Events.Any(item => item.EventId == 255))
                    warnings.Add("Sysmon reported an internal error; some telemetry may be missing.");
                alertSnapshots.SetSourceWarnings("Sysmon polling", warnings);
                await IngestAsync(snapshot.Events, token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                _alertStoreReady = false;
                alertSnapshots.SetSourceWarnings("Sysmon polling", ["Sysmon polling failed; collection will be retried."]);
                logger.LogWarning(exception, "Sysmon polling failed.");
            }
        } while (await timer.WaitForNextTickAsync(token));
    }

    private async Task PushAsync(ChannelReader<SysmonObservation> reader, CancellationToken token)
    {
        while (await reader.WaitToReadAsync(token))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(150), token);
            var batch = new List<SysmonObservation>(MaximumBatchSize);
            while (batch.Count < MaximumBatchSize && reader.TryRead(out var item)) batch.Add(item);
            var dropped = Interlocked.Read(ref _dropped);
            if (dropped > 0) alertSnapshots.SetSourceWarnings("Sysmon delivery",
                [$"Sysmon live queue dropped {dropped} events; bounded polling may recover recent review events."]);
            if (batch.Any(item => item.EventId == 255)) alertSnapshots.SetSourceWarnings("Sysmon live",
                ["Sysmon reported an internal error; some telemetry may be missing."]);
            try { await IngestAsync(batch, token); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                _alertStoreReady = false;
                alertSnapshots.SetSourceWarnings("Sysmon persistence", ["Sysmon review events could not be stored; bounded polling will retry."]);
                logger.LogWarning(exception, "Sysmon event processing failed.");
            }
        }
    }

    private async Task IngestAsync(IEnumerable<SysmonObservation> events, CancellationToken token)
    {
        var snapshot = SysmonAlertBatch.Create(events, DateTimeOffset.UtcNow);
        if (snapshot.Events.Count == 0) return;
        if (!_alertStoreReady)
        {
            await alerts.InitializeAsync(token);
            _alertStoreReady = true;
        }
        await alerts.IngestAsync(snapshot, token);
        alertSnapshots.SetSourceWarnings("Sysmon persistence", []);
        alertSnapshots.Publish(await alerts.ReadSnapshotAsync(token));
    }
}
