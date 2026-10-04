namespace Downpour.Service;

/// <summary>Retains bounded health signals for live event subscriptions across polling refreshes.</summary>
public sealed class SecurityEventPushStatus
{
    private const int MaximumWarnings = 32;
    private readonly object _warningGate = new();
    private readonly HashSet<string> _warnings = new(StringComparer.Ordinal);
    private long _droppedEvents;

    public void ReportWarning(string warning)
    {
        if (string.IsNullOrWhiteSpace(warning)) return;
        var bounded = new string(warning.Where(character => !char.IsControl(character)).Take(512).ToArray());
        if (bounded.Length == 0) return;
        lock (_warningGate)
        {
            if (_warnings.Count < MaximumWarnings) _warnings.Add(bounded);
        }
    }

    public void RecordDroppedEvent() => Interlocked.Increment(ref _droppedEvents);

    public IReadOnlyList<string> GetWarnings()
    {
        List<string> warnings;
        lock (_warningGate) warnings = _warnings.Take(MaximumWarnings).ToList();
        var dropped = Interlocked.Read(ref _droppedEvents);
        if (dropped > 0) warnings.Add($"Live event queue dropped {dropped} metadata record(s); periodic polling remains active.");
        return warnings.Take(MaximumWarnings + 1).ToArray();
    }
}
