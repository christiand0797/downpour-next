namespace Downpour.Core;

/// <summary>
/// Collects offers only from completely successful Windows Update searches. A later incomplete search
/// invalidates earlier offers so an install batch cannot silently act on a partial selection.
/// </summary>
public sealed class WindowsUpdateSearchBatch<T>
{
    private readonly List<T> _updates = [];
    private int _searches;

    public string? Failure { get; private set; }
    public bool IsComplete => _searches > 0 && Failure is null;
    public IReadOnlyList<T> Updates => IsComplete ? _updates : Array.Empty<T>();

    public bool AddResult(int resultCode, int warningCount, Func<IEnumerable<T>> readUpdates)
    {
        ArgumentNullException.ThrowIfNull(readUpdates);
        if (Failure is not null) return false;
        _searches++;
        Failure = resultCode switch
        {
            2 when warningCount < 0 => "Windows Update returned invalid search warning metadata; no complete result is available.",
            2 when warningCount > 0 => "Windows Update completed with search warnings; the result may be incomplete.",
            2 => null,
            3 => "Windows Update succeeded with errors; the search result is incomplete.",
            4 => "Windows Update failed the search; no complete result is available.",
            5 => "Windows Update aborted the search; no complete result is available.",
            _ => $"Windows Update did not complete the search (result {resultCode}); no complete result is available.",
        };
        if (Failure is not null)
        {
            _updates.Clear();
            return false;
        }

        try { _updates.AddRange(readUpdates()); }
        catch
        {
            _updates.Clear();
            Failure = "Windows Update's offers could not be read; no complete result is available.";
            throw;
        }
        return true;
    }
}
