using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Thread-safe, in-memory store for the latest Sysmon snapshot.</summary>
public sealed class SysmonSnapshotStore
{
    private SysmonSnapshot? _current;
    private readonly object _gate = new();

    public SysmonSnapshot? Current
    {
        get
        {
            lock (_gate) return _current;
        }
    }

    public void Publish(SysmonSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        lock (_gate) _current = snapshot;
    }
}