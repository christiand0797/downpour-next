using System.Text.Json;

namespace Downpour.Core;

public sealed record LedgerEntry(DateTimeOffset AtUtc, LocalChange Change);

/// <summary>
/// Keeps a bounded history of local changes so "what appeared on this PC last Tuesday" survives a restart. The
/// presentation digest is session-scoped by design; this ledger is the durable answer, and it stores only the change
/// keys the sensors already produce (never commands, paths beyond the key, or file content). Identical changes seen in
/// one append are recorded once, and the same change repeating within an hour is not re-appended, so a one-second
/// refresh cannot flood the history.
/// </summary>
public sealed class ChangeLedger
{
    public const int MaximumEntries = 2_000;
    private static readonly TimeSpan RepeatWindow = TimeSpan.FromHours(1);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly List<LedgerEntry> _entries = [];
    private readonly object _gate = new();

    public ChangeLedger(TimeSpan? retention = null)
    {
        Retention = retention ?? TimeSpan.FromDays(90);
        if (Retention < TimeSpan.FromDays(1) || Retention > TimeSpan.FromDays(365))
            throw new ArgumentOutOfRangeException(nameof(retention), "Retention must be between one day and one year.");
    }

    public TimeSpan Retention { get; }

    public int Count { get { lock (_gate) return _entries.Count; } }

    public IReadOnlyList<LedgerEntry> Append(IEnumerable<LocalChange> changes, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(changes);
        var added = new List<LedgerEntry>();
        lock (_gate)
        {
            foreach (var change in changes.Distinct())
            {
                if (_entries.Any(entry => entry.Change == change && at - entry.AtUtc < RepeatWindow && entry.AtUtc <= at)) continue;
                var entry = new LedgerEntry(at, change);
                _entries.Add(entry);
                added.Add(entry);
            }
            if (_entries.Count > MaximumEntries)
                _entries.RemoveRange(0, _entries.Count - MaximumEntries);
        }
        return added;
    }

    public IReadOnlyList<LedgerEntry> Since(DateTimeOffset from)
    {
        lock (_gate) return _entries.Where(entry => entry.AtUtc >= from).OrderBy(entry => entry.AtUtc).ToArray();
    }

    public int Prune(DateTimeOffset now)
    {
        lock (_gate)
        {
            var cutoff = now - Retention;
            var removed = _entries.RemoveAll(entry => entry.AtUtc < cutoff || entry.AtUtc > now + TimeSpan.FromDays(1));
            return removed;
        }
    }

    public string Serialize()
    {
        lock (_gate) return JsonSerializer.Serialize(_entries, Json);
    }

    public static ChangeLedger Deserialize(string json, TimeSpan? retention = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        var ledger = new ChangeLedger(retention);
        if (json.Length > 2 * 1024 * 1024) return ledger;
        try
        {
            var entries = JsonSerializer.Deserialize<List<LedgerEntry>>(json, Json);
            if (entries is null) return ledger;
            foreach (var entry in entries.Where(entry => entry.Change is not null).OrderBy(entry => entry.AtUtc).Take(MaximumEntries))
                ledger._entries.Add(entry);
        }
        catch (JsonException) { }
        return ledger;
    }
}
