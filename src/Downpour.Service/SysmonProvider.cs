using System.Diagnostics.Eventing.Reader;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Reads Sysmon event log for process creation, network connections, file creation, registry modifications, and other security-relevant events.<//// </summary>
public sealed class SysmonProvider
{
    public const int MaximumEvents = 256;
    private const int MaximumEventsPerSource = 96;
    private static readonly TimeSpan Lookback = TimeSpan.FromHours(24);

    private static readonly EventSource[] Sources =
    [
        new("Microsoft-Windows-Sysmon/Operational", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]),
        new("Microsoft-Windows-Sysmon/Operational", [255, 256, 257, 258]),
    ];

    public SysmonSnapshot Capture()
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var events = new List<SysmonObservation>();
        var warnings = new List<string>();
        var queried = 0;

        if (!IsSysmonLogPresent())
            return new SysmonSnapshot(1, capturedAt, [], 0, ["Sysmon is not installed on this PC, so Sysmon telemetry is unavailable."]);

        foreach (var source in Sources)
        {
            try
            {
                events.AddRange(ReadSource(source, capturedAt));
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

        return new SysmonSnapshot(1, capturedAt, bounded, queried, warnings.Take(64).ToArray());
    }

    public static IReadOnlyCollection<int> WatchedEventIds => SysmonCatalog.WatchedEventIds;

    /// <summary>True when the Sysmon operational channel is registered on this machine.</summary>
    public static bool IsSysmonLogPresent()
    {
        try
        {
            using var configuration = new EventLogConfiguration(Sources[0].LogName);
            return true;
        }
        catch (Exception exception) when (exception is EventLogNotFoundException or EventLogException or UnauthorizedAccessException)
        {
            // Access denied still means the channel exists.
            return exception is UnauthorizedAccessException;
        }
    }

    /// <summary>Subscribes to allow-listed future Sysmon events.</summary>
    public IDisposable SubscribePush(Action<SysmonObservation> onObservation, Action<string> onWarning, out int activeSources)
    {
        ArgumentNullException.ThrowIfNull(onObservation);
        ArgumentNullException.ThrowIfNull(onWarning);
        var watchers = new List<EventLogWatcher>();
        if (!IsSysmonLogPresent())
        {
            // Not an error: Sysmon is an optional Microsoft Sysinternals tool. Say so once instead of a read error per source.
            onWarning("Sysmon is not installed, so Sysmon telemetry is unavailable. Install Microsoft Sysinternals Sysmon to enable it.");
            activeSources = 0;
            return new EventWatcherGroup(watchers);
        }
        foreach (var source in Sources)
        {
            EventLogWatcher? watcher = null;
            try
            {
                var ids = string.Join(" or ", source.EventIds.Select(id => $"EventID={id}"));
                var query = new EventLogQuery(source.LogName, PathType.LogName, $"*[System[({ids})]]")
                {
                    TolerateQueryErrors = false
                };
                watcher = new EventLogWatcher(query, null, readExistingEvents: false);
                var capturedSource = source;
                watcher.EventRecordWritten += (_, args) =>
                {
                    if (args.EventException is not null)
                    {
                        onWarning($"Live Sysmon event subscription encountered a read error for {capturedSource.LogName}; periodic polling remains active.");
                        return;
                    }

                    using var record = args.EventRecord;
                    if (record is null) return;
                    try
                    {
                        var created = ToUtc(record.TimeCreated);
                        if (created is null || created > DateTimeOffset.UtcNow.AddMinutes(1)) return;
                        var observation = CreateObservation(capturedSource.LogName, record.ProviderName, record.Id, record.RecordId, created);
                        if (observation is not null) onObservation(observation);
                    }
                    catch (Exception exception) when (exception is EventLogException or InvalidOperationException or ArgumentException or System.Security.SecurityException)
                    {
                        onWarning($"A live Sysmon event from {capturedSource.LogName} could not be minimized; periodic polling remains active.");
                    }
                };
                watcher.Enabled = true;
                watchers.Add(watcher);
                watcher = null;
            }
            catch (Exception exception) when (exception is EventLogNotFoundException or EventLogException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or System.Security.SecurityException)
            {
                onWarning($"Live Sysmon event subscription unavailable for {source.LogName}; periodic polling remains active.");
            }
            finally
            {
                watcher?.Dispose();
            }
        }

        activeSources = watchers.Count;
        return new EventWatcherGroup(watchers);
    }

    public static SysmonObservation? CreateObservation(
        string logName, string? provider, int eventId, long? recordId, DateTimeOffset? createdAtUtc)
    {
        if (!SysmonCatalog.TryGetRule(logName, eventId, out var rule)) return null;

        return new SysmonObservation(
            logName,
            Sanitize(provider, 128),
            eventId,
            recordId is >= 0 ? recordId : null,
            createdAtUtc,
            rule.Severity,
            rule.Technique,
            rule.Summary,
            1);
    }

    private static IReadOnlyList<SysmonObservation> ReadSource(EventSource source, DateTimeOffset capturedAt)
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
        var results = new List<SysmonObservation>(MaximumEventsPerSource);
        while (results.Count < MaximumEventsPerSource && reader.ReadEvent() is { } record)
        {
            using (record)
            {
                if (record.Id is < 0 or > ushort.MaxValue) continue;
                var created = ToUtc(record.TimeCreated);
                if (created is { } timestamp && timestamp > capturedAt + TimeSpan.FromMinutes(1)) continue;
                var observation = CreateObservation(source.LogName, record.ProviderName, record.Id, record.RecordId, created);
                if (observation is not null) results.Add(observation);
            }
        }

        return results;
    }

    private static string Sanitize(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value)) return "Unknown provider";
        var clean = new string(value.Where(character => !char.IsControl(character)).Take(maximumLength).ToArray()).Trim();
        return clean.Length == 0 ? "Unknown provider" : clean;
    }

    private static DateTimeOffset? ToUtc(DateTime? value) => value is { } time
        ? new DateTimeOffset(DateTime.SpecifyKind(time, time.Kind == DateTimeKind.Unspecified ? DateTimeKind.Local : time.Kind)).ToUniversalTime()
        : null;

    private sealed class EventWatcherGroup(List<EventLogWatcher> watchers) : IDisposable
    {
        public void Dispose()
        {
            foreach (var watcher in watchers)
            {
                try { watcher.Enabled = false; } catch (EventLogException) { }
                watcher.Dispose();
            }
        }

        private sealed record EventSource(string LogName, int[] EventIds);
    }
    private sealed record EventSource(string LogName, int[] EventIds);
}