using Downpour.Contracts;

namespace Downpour.Service;

public sealed class SecurityAlertSnapshotStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, string[]> _sourceWarnings = new(StringComparer.Ordinal);
    private SecurityAlertSnapshot _latest = new(1, DateTimeOffset.UtcNow, 0, [], ["Security alert storage is starting."]);
    private SecurityAlertSnapshot _current = new(1, DateTimeOffset.UtcNow, 0, [], ["Security alert storage is starting."]);
    public SecurityAlertSnapshot Current => Volatile.Read(ref _current);
    public void Publish(SecurityAlertSnapshot snapshot)
    {
        lock (_gate)
        {
            _latest = snapshot;
            Refresh();
        }
    }

    /// <summary>Retains bounded sensor health across alert publications from other workers.</summary>
    internal void SetSourceWarnings(string source, IEnumerable<string> warnings)
    {
        var bounded = warnings.Where(value => value is { Length: > 0 and <= 512 } && !value.Any(char.IsControl))
            .Distinct(StringComparer.Ordinal).Take(4).ToArray();
        lock (_gate)
        {
            if (bounded.Length == 0) _sourceWarnings.Remove(source);
            else
            {
                if (!_sourceWarnings.ContainsKey(source) && _sourceWarnings.Count >= 8)
                    throw new InvalidOperationException("Too many sensor health sources.");
                _sourceWarnings[source] = bounded;
            }
            Refresh();
        }
    }

    private void Refresh() => Interlocked.Exchange(ref _current, _latest with
    {
        Warnings = _sourceWarnings.Values.SelectMany(value => value).Concat(_latest.Warnings)
            .Distinct(StringComparer.Ordinal).Take(32).ToArray()
    });
}
