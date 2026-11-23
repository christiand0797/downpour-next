namespace Downpour.Core;

/// <summary>One remembered DNS name: its hash and when this PC first and most recently resolved it.</summary>
public sealed record DomainObservation(string Hash, DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc);

/// <summary>What one capture changed: which hashes are new to this PC, the baseline to store, and how many names left it.</summary>
public sealed record DomainBaselineUpdate(bool FirstRun, IReadOnlyList<string> NewHashes, DomainBaseline Baseline, int Evicted);

/// <summary>
/// Bounded, deterministic memory of the DNS names this PC has resolved. Only SHA-256 hashes and two dates are kept, so the
/// file cannot become a browsing history. The first capture is a baseline, not a finding.
///
/// When the baseline is full the <em>least recently resolved</em> name leaves first, ties broken by hash. That ordering is
/// the point: an arbitrary subset (the previous <c>Take(n)</c>) could drop a name that is still in the resolver cache, so the
/// next capture called it new and raised the same finding again. A name resolved today now always survives eviction while
/// there is room, and repeating the same capture reports nothing new.
/// </summary>
public sealed class DomainBaseline
{
    public const int DefaultCapacity = 20_000;
    public const int MinimumCapacity = 100;
    public const int MaximumCapacity = 100_000;
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);

    private readonly Dictionary<string, (DateTimeOffset First, DateTimeOffset Last)> _seen;

    public DomainBaseline(IEnumerable<DomainObservation>? observations = null, int capacity = DefaultCapacity)
    {
        _seen = new Dictionary<string, (DateTimeOffset, DateTimeOffset)>(StringComparer.Ordinal);
        if (observations is not null)
        {
            foreach (var observation in observations)
            {
                if (!IsHash(observation.Hash)) continue;
                var last = observation.LastSeenUtc < observation.FirstSeenUtc ? observation.FirstSeenUtc : observation.LastSeenUtc;
                if (_seen.TryGetValue(observation.Hash, out var existing))
                    _seen[observation.Hash] = (earlier(existing.First, observation.FirstSeenUtc), later(existing.Last, last));
                else
                    _seen[observation.Hash] = (observation.FirstSeenUtc, last);
            }
        }
        Trim(capacity);
    }

    public int Count => _seen.Count;

    /// <summary>When this PC's earliest remembered name was first resolved, or null when nothing is remembered.</summary>
    public DateTimeOffset? EstablishedUtc => _seen.Count == 0 ? null : _seen.Values.Min(value => value.First);

    public bool Knows(string hash) => _seen.ContainsKey(hash);

    public DateTimeOffset? FirstSeen(string hash) => _seen.TryGetValue(hash, out var value) ? value.First : null;

    /// <summary>
    /// Records one capture. Names already remembered only move their last-seen date; unknown names are new. A first run
    /// (empty baseline) still reports its hashes, so the caller can decide to stay silent instead of alerting on every name.
    /// </summary>
    public DomainBaselineUpdate Observe(IEnumerable<string> hashes, DateTimeOffset nowUtc, int capacity = DefaultCapacity)
    {
        ArgumentNullException.ThrowIfNull(hashes);
        if (capacity is < MinimumCapacity or > MaximumCapacity) throw new ArgumentOutOfRangeException(nameof(capacity));
        var firstRun = _seen.Count == 0;
        var updated = new Dictionary<string, (DateTimeOffset First, DateTimeOffset Last)>(_seen, StringComparer.Ordinal);
        var newHashes = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var hash in hashes)
        {
            if (!IsHash(hash) || !seen.Add(hash)) continue;
            if (updated.TryGetValue(hash, out var existing))
            {
                updated[hash] = (existing.First, later(existing.Last, nowUtc));
                continue;
            }
            updated[hash] = (nowUtc, nowUtc);
            newHashes.Add(hash);
        }
        var baseline = new DomainBaseline(updated.Select(pair => new DomainObservation(pair.Key, pair.Value.First, pair.Value.Last)), capacity);
        return new DomainBaselineUpdate(firstRun, newHashes, baseline, updated.Count - baseline.Count);
    }

    /// <summary>Every remembered name, least recently resolved first, so a written file is stable and bounded.</summary>
    public IReadOnlyList<DomainObservation> Snapshot() => _seen
        .Select(pair => new DomainObservation(pair.Key, pair.Value.First, pair.Value.Last))
        .OrderBy(observation => observation.LastSeenUtc)
        .ThenBy(observation => observation.Hash, StringComparer.Ordinal)
        .ToArray();

    private void Trim(int capacity)
    {
        if (capacity is < MinimumCapacity or > MaximumCapacity) capacity = DefaultCapacity;
        if (_seen.Count <= capacity) return;
        foreach (var hash in _seen.OrderBy(pair => pair.Value.Last).ThenBy(pair => pair.Key, StringComparer.Ordinal)
                     .Take(_seen.Count - capacity).Select(pair => pair.Key).ToArray())
            _seen.Remove(hash);
    }

    private static DateTimeOffset earlier(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;
    private static DateTimeOffset later(DateTimeOffset a, DateTimeOffset b) => a >= b ? a : b;

    public static bool IsHash(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
