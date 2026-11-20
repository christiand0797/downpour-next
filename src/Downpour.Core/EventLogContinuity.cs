namespace Downpour.Core;

/// <summary>A per-channel cursor: the last record the service actually ingested, with its content hash.</summary>
public sealed record EventCursor(string LogName, long LastRecordId, string LastRecordHash, DateTimeOffset UpdatedUtc);

public enum CatchUpOutcome { Current, CatchUp, Lost }

public sealed record CatchUpPlan(
    CatchUpOutcome Outcome,
    long StartRecordId,
    long FirstAvailableRecordId,
    long LastAvailableRecordId,
    long MissingRecords,
    string Note);

/// <summary>
/// Keeps event ingestion honest across restarts. A cursor only moves forward and only for the channel it names, so a
/// replayed or stale record cannot rewind ingestion. On start the plan states whether the service can catch up or
/// whether records were already rolled out of the log — the blind window is reported instead of being silent.
/// </summary>
public static class EventLogContinuity
{
    public const long MaximumRecordId = 9_223_372_036_854_775_807;

    public static EventCursor? Advance(EventCursor? cursor, string logName, long recordId, string hash, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logName);
        ArgumentException.ThrowIfNullOrWhiteSpace(hash);
        if (recordId < 0 || recordId > MaximumRecordId) throw new ArgumentOutOfRangeException(nameof(recordId));
        if (cursor is not null && !string.Equals(cursor.LogName, logName, StringComparison.OrdinalIgnoreCase)) return null;
        if (cursor is not null && recordId <= cursor.LastRecordId) return null;
        return new EventCursor(logName, recordId, hash, now);
    }

    public static CatchUpPlan Plan(EventCursor? cursor, string logName, long firstAvailableRecordId, long lastAvailableRecordId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logName);
        if (firstAvailableRecordId < 0 || lastAvailableRecordId < firstAvailableRecordId)
            throw new ArgumentOutOfRangeException(nameof(firstAvailableRecordId));
        if (cursor is null)
            return new(CatchUpOutcome.CatchUp, firstAvailableRecordId, firstAvailableRecordId, lastAvailableRecordId, 0,
                $"First run for {logName}: ingesting from record {firstAvailableRecordId}.");
        if (!string.Equals(cursor.LogName, logName, StringComparison.OrdinalIgnoreCase))
            return new(CatchUpOutcome.CatchUp, firstAvailableRecordId, firstAvailableRecordId, lastAvailableRecordId, 0,
                $"The stored cursor belongs to another channel: ingesting {logName} from record {firstAvailableRecordId}.");
        var next = cursor.LastRecordId + 1;
        if (firstAvailableRecordId <= next)
            return next > lastAvailableRecordId
                ? new(CatchUpOutcome.Current, next, firstAvailableRecordId, lastAvailableRecordId, 0, $"{logName} is current.")
                : new(CatchUpOutcome.CatchUp, next, firstAvailableRecordId, lastAvailableRecordId, 0,
                    $"{logName}: catching up {lastAvailableRecordId - next + 1:N0} record(s) since {cursor.UpdatedUtc:yyyy-MM-dd HH:mm} UTC.");
        var missing = firstAvailableRecordId - next;
        return new(CatchUpOutcome.Lost, firstAvailableRecordId, firstAvailableRecordId, lastAvailableRecordId, missing,
            $"{logName}: {missing:N0} record(s) were already rolled out of the log since the last run; that window cannot be recovered.");
    }
}
