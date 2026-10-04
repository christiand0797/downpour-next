using Downpour.Contracts;

namespace Downpour.Service;

public sealed class SecurityAlertSnapshotStore
{
    private SecurityAlertSnapshot _current = new(1, DateTimeOffset.UtcNow, 0, [], ["Security alert storage is starting."]);
    public SecurityAlertSnapshot Current => Volatile.Read(ref _current);
    public void Publish(SecurityAlertSnapshot snapshot) => Interlocked.Exchange(ref _current, snapshot);
}
