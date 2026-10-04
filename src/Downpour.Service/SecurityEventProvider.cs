using System.Diagnostics.Eventing.Reader;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Reads a fixed set of recent security-relevant Windows events without collecting event message bodies.</summary>
public sealed class SecurityEventProvider
{
    public const int MaximumEvents = 256;
    private const int MaximumEventsPerSource = 96;
    private const int BruteForceThreshold = 10;
    private const int BruteForceWindowSeconds = 300;
    private static readonly TimeSpan Lookback = TimeSpan.FromHours(24);

    private static readonly EventSource[] Sources =
    [
        new("System", [7045, 104]),
        new("Security", [4698, 4699, 4720, 4726, 4732, 4728, 4740, 4776, 1102, 4625, 4672, 4673, 4688, 4663, 4697, 4738]),
        new("Microsoft-Windows-PowerShell/Operational", [4104]),
        new("Microsoft-Windows-Windows Defender/Operational", [5001, 5007, 5010, 5012, 1116, 1117, 5004, 5003]),
        new("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", [21, 22, 24, 25]),
        new("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", [1149]),
        new("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", [5156, 5157, 5152])
    ];

    public SecurityEventSnapshot Capture()
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var events = new List<SecurityEventObservation>();
        var warnings = new List<string>();
        var queried = 0;

        foreach (var source in Sources)
        {
            try
            {
                events.AddRange(ReadSource(source, capturedAt));
                if (source.LogName.Equals("Security", StringComparison.OrdinalIgnoreCase) &&
                    TryReadFailedLogonBurst(capturedAt, warnings) is { } burst)
                {
                    events.Add(burst);
                }
                queried++;
            }
            catch (EventLogNotFoundException)
            {
                warnings.Add($"Event source unavailable: {source.LogName}.");
            }
            catch (UnauthorizedAccessException)
            {
                warnings.Add($"Permission denied reading {source.LogName}; run with an account permitted to read this log.");
            }
            catch (EventLogException)
            {
                warnings.Add($"Windows could not read {source.LogName}; the channel may be disabled or restricted.");
            }
            catch (InvalidOperationException)
            {
                warnings.Add($"Windows event source {source.LogName} is currently unavailable.");
            }
        }

        var bounded = events
            .OrderByDescending(item => item.CreatedAtUtc)
            .ThenByDescending(item => item.RecordId)
            .Take(MaximumEvents)
            .ToArray();

        return new SecurityEventSnapshot(1, capturedAt, bounded, queried, warnings.Take(64).ToArray());
    }

    public static IReadOnlyCollection<int> WatchedEventIds => SecurityEventCatalog.WatchedEventIds;

    public static SecurityEventObservation? CreateObservation(
        string logName, string? provider, int eventId, long? recordId, DateTimeOffset? createdAtUtc)
    {
        if (!SecurityEventCatalog.TryGetRule(logName, eventId, out var rule)) return null;

        return new SecurityEventObservation(
            logName,
            Sanitize(provider, 128),
            eventId,
            recordId is >= 0 ? recordId : null,
            createdAtUtc,
            rule.Severity,
            rule.Technique,
            rule.Summary,
            eventId == 4625 ? BruteForceThreshold : 1);
    }

    private static IReadOnlyList<SecurityEventObservation> ReadSource(EventSource source, DateTimeOffset capturedAt)
    {
        var ids = string.Join(" or ", source.EventIds.Select(id => $"EventID={id}"));
        var ageMilliseconds = (long)Lookback.TotalMilliseconds;
        var xpath = $"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {ageMilliseconds}]]]";
        var query = new EventLogQuery(source.LogName, PathType.LogName, xpath)
        {
            ReverseDirection = true,
            TolerateQueryErrors = false
        };

        using var reader = new EventLogReader(query);
        var results = new List<SecurityEventObservation>(MaximumEventsPerSource);
        while (results.Count < MaximumEventsPerSource && reader.ReadEvent() is { } record)
        {
            using (record)
            {
                if (record.Id is < 0 or > ushort.MaxValue) continue;
                if (record.Id == 4625) continue;
                DateTimeOffset? created = record.TimeCreated is { } time
                    ? new DateTimeOffset(DateTime.SpecifyKind(time, time.Kind == DateTimeKind.Unspecified ? DateTimeKind.Local : time.Kind)).ToUniversalTime()
                    : null;
                if (created is { } timestamp && timestamp > capturedAt + TimeSpan.FromMinutes(1)) continue;
                var observation = CreateObservation(source.LogName, record.ProviderName, record.Id, record.RecordId, created);
                if (observation is not null) results.Add(observation);
            }
        }

        return results;
    }

    public static SecurityEventObservation? CreateFailedLogonBurst(int count, long? latestRecordId, DateTimeOffset capturedAt)
    {
        if (count < BruteForceThreshold) return null;
        if (!SecurityEventCatalog.TryGetRule("Security", 4625, out var rule))
            throw new InvalidOperationException("Brute-force event classification is missing.");
        return new SecurityEventObservation("Security", "Microsoft-Windows-Security-Auditing", 4625, latestRecordId,
            capturedAt.ToUniversalTime(), rule.Severity, rule.Technique, rule.Summary, Math.Clamp(count, BruteForceThreshold, 100));
    }

    private static SecurityEventObservation? TryReadFailedLogonBurst(DateTimeOffset capturedAt, List<string> warnings)
    {
        try
        {
            var queryText = $"*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= {BruteForceWindowSeconds * 1000}]]]";
            var query = new EventLogQuery("Security", PathType.LogName, queryText) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            long? latestRecordId = null;
            var count = 0;
            while (count < 100 && reader.ReadEvent() is { } record)
            {
                using (record)
                {
                    if (record.Id != 4625) continue;
                    latestRecordId ??= record.RecordId;
                    count++;
                }
            }
            return CreateFailedLogonBurst(count, latestRecordId, capturedAt);
        }
        catch (UnauthorizedAccessException)
        {
            warnings.Add("Permission denied while checking the five-minute failed-logon burst window.");
            return null;
        }
        catch (EventLogException)
        {
            warnings.Add("Windows could not evaluate the five-minute failed-logon burst window.");
            return null;
        }
    }

    private static string Sanitize(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value)) return "Unknown provider";
        var clean = new string(value.Where(character => !char.IsControl(character)).Take(maximumLength).ToArray()).Trim();
        return clean.Length == 0 ? "Unknown provider" : clean;
    }

    private sealed record EventSource(string LogName, int[] EventIds);
}
