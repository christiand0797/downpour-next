namespace Downpour.Service;

/// <summary>
/// Stale-while-revalidate cache for a pipe worker's snapshot. Clients polling every second get the latest finished
/// snapshot immediately; when it is older than <see cref="RefreshAfter"/> one background capture starts, so a slow
/// collector (firewall, hardening, WMI) never makes a request wait and never runs more than once at a time.
/// Only the very first request waits for a capture.
/// </summary>
public sealed class SnapshotCache<T>(Func<T> capture, TimeSpan refreshAfter, ILogger? logger = null) where T : class
{
    private readonly object _gate = new();
    private T? _value;
    private DateTimeOffset _capturedAt;
    private Task<T>? _inFlight;

    public TimeSpan RefreshAfter { get; } = refreshAfter;

    /// <summary>Starts the first capture in the background at service start, so the first request is answered from cache.</summary>
    public void Warm()
    {
        lock (_gate)
            if (_value is null) _inFlight ??= Task.Run(CaptureAndStore, CancellationToken.None);
        _inFlight?.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
    }

    public async Task<T> GetAsync(CancellationToken token)
    {
        Task<T>? wait = null;
        T? current;
        lock (_gate)
        {
            current = _value;
            if (current is null || DateTimeOffset.UtcNow - _capturedAt >= RefreshAfter)
            {
                _inFlight ??= Task.Run(CaptureAndStore, CancellationToken.None);
                if (current is null) wait = _inFlight;
            }
        }
        return wait is null ? current! : await wait.WaitAsync(token).ConfigureAwait(false);
    }

    private T CaptureAndStore()
    {
        try
        {
            var value = capture();
            lock (_gate)
            {
                _value = value;
                _capturedAt = DateTimeOffset.UtcNow;
            }
            return value;
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "A snapshot capture for {Type} failed.", typeof(T).Name);
            lock (_gate)
            {
                // Keep serving the previous snapshot; retry on the next request after the refresh interval.
                if (_value is not null) _capturedAt = DateTimeOffset.UtcNow;
                else throw;
                return _value;
            }
        }
        finally
        {
            lock (_gate) _inFlight = null;
        }
    }
}
