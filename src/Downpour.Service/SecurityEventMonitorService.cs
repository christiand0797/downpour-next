using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>Continuously refreshes local Windows event metadata and its persistent alert projection.</summary>
public sealed class SecurityEventMonitorService(
    SecurityEventProvider provider,
    SecurityEventSnapshotStore store,
    SecurityEventPushStatus pushStatus,
    SecurityAlertRepository alerts,
    SecurityAlertSnapshotStore alertSnapshots,
    ILogger<SecurityEventMonitorService> logger) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);
    private bool _alertStoreReady;
    private IReadOnlyDictionary<string, EventCursor> _cursors = new Dictionary<string, EventCursor>(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset? _lastClockReading;
    private DateTimeOffset _clockSavedAt;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await TryInitializeAlertStoreAsync(stoppingToken);
        using var timer = new PeriodicTimer(PollInterval);
        while (!stoppingToken.IsCancellationRequested)
        {
            SecurityEventSnapshot? snapshot = null;
            EventLogCapture? capture = null;
            try
            {
                var previous = _cursors;
                capture = await Task.Run(() => provider.CaptureWithCursors(previous), stoppingToken);
                snapshot = capture.Snapshot;
                // A backwards wall clock can revive expired evidence and reorder history, so it is said out loud.
                var clockNow = DateTimeOffset.UtcNow;
                var finding = ClockIntegrity.Evaluate(new ClockEvidence(
                    clockNow, _lastClockReading, TimeSpan.FromMilliseconds(Environment.TickCount64), BootUtc: null));
                if (finding.Verdict is ClockVerdict.BackwardJump or ClockVerdict.MonotonicMismatch)
                    snapshot = snapshot with
                    {
                        Warnings = snapshot.Warnings.Concat([$"System clock: {finding.Detail}"]).Take(64).ToArray()
                    };
                _lastClockReading = clockNow;
                snapshot = snapshot with
                {
                    Warnings = snapshot.Warnings.Concat(pushStatus.GetWarnings()).Distinct(StringComparer.Ordinal).Take(64).ToArray()
                };
                store.Publish(snapshot);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Windows event monitor refresh failed.");
                var warning = new SecurityEventSnapshot(1, DateTimeOffset.UtcNow, [], 0,
                    ["Windows event monitoring is unavailable; see the local service log for details."]);
                store.Publish(warning);
                await PublishAlertWarningAsync("Windows event monitoring is unavailable; existing local alerts are retained.", stoppingToken);
            }

            if (snapshot is not null)
            {
                if (!_alertStoreReady) await TryInitializeAlertStoreAsync(stoppingToken);
                if (_alertStoreReady)
                {
                    try
                    {
                        await alerts.IngestAsync(snapshot, stoppingToken);
                        // Readability decides whether a quiet rule is quiet or blind, so it is stored with the alerts.
                        if (capture?.Channels is { Count: > 0 } channelHealth)
                            await alerts.SaveChannelHealthAsync(channelHealth, stoppingToken);
                        if (capture is { Resets.Count: > 0 } cleared)
                        {
                            foreach (var logName in cleared.Resets)
                            {
                                await alerts.DeleteEventCursorAsync(logName, stoppingToken);
                                _cursors = _cursors.Where(pair => !string.Equals(pair.Key, logName, StringComparison.OrdinalIgnoreCase))
                                    .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
                            }
                        }
                        if (capture is { Cursors.Count: > 0 } advanced)
                        {
                            await alerts.SaveEventCursorsAsync(advanced.Cursors, stoppingToken);
                            _cursors = advanced.Cursors.ToDictionary(cursor => cursor.LogName, StringComparer.OrdinalIgnoreCase);
                        }
                        if (_lastClockReading is { } clockReading && clockReading - _clockSavedAt > TimeSpan.FromMinutes(5))
                        {
                            await alerts.SaveClockReadingAsync(clockReading, stoppingToken);
                            _clockSavedAt = clockReading;
                        }
                        await PublishAlertSnapshotAsync(snapshot, stoppingToken);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception exception)
                    {
                        _alertStoreReady = false;
                        logger.LogWarning(exception, "Event observations are live, but persistent alert storage could not be refreshed.");
                        await PublishAlertWarningAsync("Event observations are available; persistent alert storage could not be refreshed.", stoppingToken);
                    }
                }

                logger.LogInformation("Windows event monitor refreshed: {EventCount} observations, {SourceCount} sources.",
                    snapshot.Events.Count, snapshot.SourcesQueried);
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

    private async Task TryInitializeAlertStoreAsync(CancellationToken token)
    {
        try
        {
            await alerts.InitializeAsync(token);
            _cursors = await alerts.ReadEventCursorsAsync(token);
            _lastClockReading = await alerts.ReadClockReadingAsync(token);
            _clockSavedAt = _lastClockReading ?? DateTimeOffset.MinValue;
            var initial = await alerts.ReadSnapshotAsync(token);
            alertSnapshots.Publish(initial with { Warnings = ["Waiting for the first Windows event monitor refresh."] });
            _alertStoreReady = true;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            logger.LogError(exception, "Persistent local security-alert storage is unavailable; event collection will continue and storage will be retried.");
            _alertStoreReady = false;
            alertSnapshots.Publish(new SecurityAlertSnapshot(1, DateTimeOffset.UtcNow, 0, [],
                ["Persistent local security-alert storage is unavailable; retrying."]));
        }
    }

    private async Task PublishAlertSnapshotAsync(SecurityEventSnapshot source, CancellationToken token)
    {
        var current = await alerts.ReadSnapshotAsync(token);
        var warnings = source.Warnings.ToList();
        if (source.SourcesQueried < 7)
            warnings.Add($"Only {source.SourcesQueried} of 7 allow-listed event channels were readable during the latest refresh.");
        if (current.Retention is { } retention) warnings.AddRange(retention.Warnings);
        alertSnapshots.Publish(current with { Warnings = warnings.Distinct(StringComparer.Ordinal).Take(32).ToArray() });
    }

    private async Task PublishAlertWarningAsync(string warning, CancellationToken token)
    {
        try
        {
            var current = await alerts.ReadSnapshotAsync(token);
            alertSnapshots.Publish(current with { Warnings = [warning] });
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            logger.LogDebug(exception, "Could not refresh retained alerts while publishing a source warning.");
            alertSnapshots.Publish(new SecurityAlertSnapshot(1, DateTimeOffset.UtcNow, 0, [], [warning]));
        }
    }
}
