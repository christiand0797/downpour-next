using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>
/// Cache of intel results (24 hours) and a log of outbound lookups without indicator values, in the protected
/// state folder. Bounded: 2,000 results and 500 log records.
/// </summary>
public sealed class IntelResultStore(string path)
{
    public static readonly TimeSpan CacheLifetime = TimeSpan.FromHours(24);
    internal const int MaximumResults = 2000;
    internal const int MaximumLog = 500;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();
    private State? _state;

    public static IntelResultStore CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var file = Path.Combine(root, "intel-results.v1.json");
        SecureJournalDirectory.RestrictExistingFile(file);
        return new IntelResultStore(file);
    }

    public DateTimeOffset? LastRunUtc { get { lock (_gate) return Current.LastRunUtc; } }
    public string LastRunStatus { get { lock (_gate) return Current.LastRunStatus; } }

    public IReadOnlyList<IntelLookupResult> Results(DateTimeOffset now)
    {
        lock (_gate) return Current.Results.Where(result => now - result.CheckedAtUtc <= CacheLifetime).ToArray();
    }

    public IReadOnlyList<IntelOutboundRecord> RecentLookups(int count)
    {
        lock (_gate) return Current.Log.TakeLast(count).Reverse().ToArray();
    }

    public bool IsCached(string service, IntelIndicator indicator, DateTimeOffset now)
    {
        lock (_gate)
            return Current.Results.Any(result => result.Service == service && result.IndicatorKind == indicator.Kind
                && result.Indicator == indicator.Value && now - result.CheckedAtUtc <= CacheLifetime);
    }

    public void Record(IntelOutboundRecord record, IntelLookupResult? cacheable)
    {
        lock (_gate)
        {
            var state = Current;
            state.Log.Add(record);
            if (state.Log.Count > MaximumLog) state.Log.RemoveRange(0, state.Log.Count - MaximumLog);
            if (cacheable is not null)
            {
                state.Results.RemoveAll(result => result.Service == cacheable.Service && result.IndicatorKind == cacheable.IndicatorKind && result.Indicator == cacheable.Indicator);
                state.Results.Add(cacheable);
                state.Results.RemoveAll(result => record.SentAtUtc - result.CheckedAtUtc > CacheLifetime);
                if (state.Results.Count > MaximumResults) state.Results.RemoveRange(0, state.Results.Count - MaximumResults);
            }
            Save(state);
        }
    }

    public void CompleteRun(DateTimeOffset at, string status)
    {
        lock (_gate)
        {
            Current.LastRunUtc = at;
            Current.LastRunStatus = status.Length <= 256 ? status : status[..256];
            Save(Current);
        }
    }

    private State Current => _state ??= Load();

    private State Load()
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 4 * 1024 * 1024 || (info.Attributes & FileAttributes.ReparsePoint) != 0) return new State();
            var state = JsonSerializer.Deserialize<State>(File.ReadAllBytes(path), Json) ?? new State();
            state.Results = state.Results.Where(result => result is not null && IntelVerdicts.All.Contains(result.Verdict)).Take(MaximumResults).ToList();
            state.Log = state.Log.Where(record => record is not null).TakeLast(MaximumLog).ToList();
            return state;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new State();
        }
    }

    private void Save(State state)
    {
        var temporary = path + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(state, Json));
            File.Move(temporary, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private sealed class State
    {
        public DateTimeOffset? LastRunUtc { get; set; }
        public string LastRunStatus { get; set; } = "Not run yet";
        public List<IntelLookupResult> Results { get; set; } = [];
        public List<IntelOutboundRecord> Log { get; set; } = [];
    }
}
