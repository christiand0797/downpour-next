using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Holds only the latest bounded event snapshot in memory; no event text is persisted.</summary>
public sealed class SecurityEventSnapshotStore
{
    private SecurityEventSnapshot _current = new(
        1, DateTimeOffset.UtcNow, [], 0, ["The Windows event monitor is starting."]);

    public SecurityEventSnapshot Current => Volatile.Read(ref _current);

    public void Publish(SecurityEventSnapshot snapshot) => Interlocked.Exchange(ref _current, snapshot);
}
