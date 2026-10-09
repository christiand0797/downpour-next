using System.Buffers.Binary;
using System.IO.Pipes;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>Continuously samples already-collected aggregate metrics while the service runs, independently of visible pages.</summary>
public sealed class LocalLearningWorker(SecurityAlertSnapshotStore alerts, SensorSettingsStore settings,
    ILogger<LocalLearningWorker> logger) : BackgroundService
{
    private readonly SystemSnapshotClient _system = new();
    private LocalLearningSnapshot _current = LocalLearningEngine.Assess(LocalLearningEngine.Empty, null, null, DateTimeOffset.UtcNow);

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => Task.WhenAll(ObserveAsync(stoppingToken), ServeAsync(stoppingToken));

    private async Task ObserveAsync(CancellationToken token)
    {
        LocalLearningStore? store = null;
        var history = LocalLearningEngine.Empty;
        var saved = history;
        var lastSave = DateTimeOffset.MinValue;
        string? loadWarning = null;
        try
        {
            store = LocalLearningStore.CreateForCurrentUser();
            (history, loadWarning) = await store.LoadAsync(DateTimeOffset.UtcNow, token);
            saved = history;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            loadWarning = "Learning storage is unavailable; observations are retained only for this service session.";
            logger.LogWarning(ex, "Local learning storage unavailable.");
        }
        while (!token.IsCancellationRequested)
        {
            try
            {
                var enabled = settings.Current.LocalLearning;
                var snapshot = enabled ? await _system.TryGetSnapshotAsync(token) : null;
                enabled = settings.Current.LocalLearning;
                var now = DateTimeOffset.UtcNow;
                var frame = !enabled || snapshot is null ? null : LocalLearningEngine.FromSnapshot(snapshot);
                var warnings = new List<string>();
                if (loadWarning is not null) warnings.Add(loadWarning);
                // A backward wall-clock adjustment must not throw out a previously valid history.
                if (!LocalLearningEngine.IsValidHistory(history, now))
                {
                    warnings.Add("The clock moved behind saved observations; learning is suspended until time catches up.");
                    frame = null;
                }
                else if (enabled && LocalLearningEngine.IsValidFrame(frame, now))
                {
                    history = LocalLearningEngine.Observe(history, frame!, now);
                }
                history = LocalLearningEngine.Prune(history, now);
                if (store is not null && !ReferenceEquals(saved, history) && (now - lastSave >= TimeSpan.FromMinutes(5) || !enabled))
                {
                    if (await store.SaveAsync(history, now, token)) { saved = history; lastSave = now; }
                    else warnings.Add("Learning history could not be saved; recent observations may be lost on restart.");
                }
                Interlocked.Exchange(ref _current, LocalLearningEngine.Assess(history, frame, alerts.Current, now, enabled, warnings));
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Local learning observation failed.");
                Interlocked.Exchange(ref _current, LocalLearningEngine.Assess(history, null, null, DateTimeOffset.UtcNow,
                    settings.Current.LocalLearning, ["The latest observation failed; previous history is retained."]));
            }
            try { await Task.Delay(TimeSpan.FromSeconds(30), token); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
        }
        if (store is not null && !ReferenceEquals(saved, history))
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try { await store.SaveAsync(history, DateTimeOffset.UtcNow, deadline.Token); }
            catch (OperationCanceledException) { logger.LogWarning("Final learning-history flush timed out."); }
        }
    }

    private async Task ServeAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(LocalLearningClient.PipeName, PipeDirection.Out, 4,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.WriteThrough, 0, 4096,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                await pipe.WaitForConnectionAsync(deadline.Token);
                var snapshot = Volatile.Read(ref _current);
                if (!settings.Current.LocalLearning)
                    snapshot = snapshot with { State = "paused", CapturedAtUtc = DateTimeOffset.UtcNow,
                        Metrics = snapshot.Metrics.Select(m => m with { Current = null, State = "paused" }).ToArray(), Recommendations = [] };
                var payload = BoundedJson.Serialize(snapshot);
                var prefix = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
                await pipe.WriteAsync(prefix, deadline.Token);
                await pipe.WriteAsync(payload, deadline.Token);
                await pipe.FlushAsync(deadline.Token);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (IOException ex) when (!token.IsCancellationRequested) { logger.LogDebug(ex, "Local learning client disconnected."); }
        }
    }
}
