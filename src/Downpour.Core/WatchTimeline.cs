using Downpour.Contracts;

namespace Downpour.Core;

public static class WatchLanes
{
    public const string Camera = "Camera";
    public const string Microphone = "Microphone";
    public const string Screen = "Screen capture";
    public const string Location = "Location";
    public const string Remote = "Remote control";

    public static readonly IReadOnlyList<string> All = [Camera, Microphone, Screen, Location, Remote];
}

/// <summary>One stretch of time when something could watch or control this PC.</summary>
public sealed record WatchInterval(string Lane, string Subject, DateTimeOffset StartUtc, DateTimeOffset EndUtc, bool Ongoing);

/// <summary>
/// Watch timeline (invented for Downpour Next): when the camera, microphone, screen capture, location or remote control
/// were in use over the last day, merged from Downpour's own start/stop watch log and Windows' per-app usage records
/// (which also cover time before Downpour was running). A start without a stop is shown as ongoing only when the
/// current snapshot confirms it is still active; otherwise it is a one-minute marker, never an invented long session.
/// </summary>
public static class WatchTimeline
{
    public const int MaximumIntervals = 400;
    private static readonly TimeSpan Marker = TimeSpan.FromMinutes(1);

    public static IReadOnlyList<WatchInterval> Build(AntiStalkerSnapshot snapshot, DateTimeOffset now, TimeSpan window)
    {
        now = now.ToUniversalTime();
        var from = now - window;
        var intervals = new List<WatchInterval>();

        foreach (var usage in snapshot.SensorUsage)
        {
            var lane = SensorLane(usage.Capability);
            if (lane is null) continue;
            if (usage.InUse)
                intervals.Add(new(lane, usage.DisplayName, usage.LastStartUtc ?? now, now, true));
            else if (usage.LastStartUtc is { } start && usage.LastStopUtc is { } stop && stop >= start)
                intervals.Add(new(lane, usage.DisplayName, start, stop, false));
        }

        var active = ActiveSubjects(snapshot);
        var open = new Dictionary<(string Lane, string Subject), DateTimeOffset>();
        foreach (var e in snapshot.Log.OrderBy(e => e.TimeUtc))
        {
            if (Classify(e) is not { } c) continue;
            var key = (c.Lane, c.Subject);
            if (c.Started)
            {
                open.TryAdd(key, e.TimeUtc);
            }
            else
            {
                var start = open.Remove(key, out var opened) ? opened : from;
                intervals.Add(new(c.Lane, c.Subject, start, e.TimeUtc, false));
            }
        }
        foreach (var ((lane, subject), start) in open)
            intervals.Add(active.Contains((lane, subject)) ? new(lane, subject, start, now, true) : new(lane, subject, start, start + Marker, false));

        return Merge(intervals
                .Where(i => i.EndUtc >= from && i.StartUtc <= now)
                .Select(i => i with { StartUtc = i.StartUtc < from ? from : i.StartUtc, EndUtc = i.EndUtc > now ? now : i.EndUtc }))
            .OrderBy(i => WatchLanes.All.ToList().IndexOf(i.Lane)).ThenBy(i => i.StartUtc)
            .Take(MaximumIntervals)
            .ToArray();
    }

    private static string? SensorLane(string capability) => capability switch
    {
        WatchCapabilities.Camera => WatchLanes.Camera,
        WatchCapabilities.Microphone => WatchLanes.Microphone,
        WatchCapabilities.ScreenCapture or WatchCapabilities.BorderlessScreenCapture => WatchLanes.Screen,
        WatchCapabilities.Location => WatchLanes.Location,
        _ => null,
    };

    /// <summary>Lane, subject and direction of a watch-log entry; null for entries that are not start/stop pairs.</summary>
    private static (string Lane, string Subject, bool Started)? Classify(WatchEvent e)
    {
        switch (e.Kind)
        {
            case WatchEventKinds.SensorStarted or WatchEventKinds.SensorStopped:
                foreach (var capability in WatchCapabilities.All)
                {
                    var prefix = WatchCapabilities.Label(capability) + " · ";
                    if (e.Subject.StartsWith(prefix, StringComparison.Ordinal) && SensorLane(capability) is { } lane)
                        return (lane, e.Subject[prefix.Length..], e.Kind == WatchEventKinds.SensorStarted);
                }
                return null;
            case WatchEventKinds.RemoteSessionStarted or WatchEventKinds.RemoteSessionEnded:
                return (WatchLanes.Remote, e.Subject, e.Kind == WatchEventKinds.RemoteSessionStarted);
            case WatchEventKinds.RemoteToolStarted or WatchEventKinds.RemoteToolStopped:
                return (WatchLanes.Remote, e.Subject, e.Kind == WatchEventKinds.RemoteToolStarted);
            default:
                return null;
        }
    }

    private static HashSet<(string, string)> ActiveSubjects(AntiStalkerSnapshot s)
    {
        var active = new HashSet<(string, string)>();
        foreach (var u in s.SensorUsage.Where(u => u.InUse))
            if (SensorLane(u.Capability) is { } lane) active.Add((lane, u.DisplayName));
        foreach (var r in s.RemoteSessions.Where(r => !r.IsCurrentSession)) active.Add((WatchLanes.Remote, $"Remote session {r.SessionId}"));
        foreach (var t in s.RemoteControl) active.Add((WatchLanes.Remote, t.Product));
        return active;
    }

    /// <summary>Joins overlapping or touching intervals of the same lane and subject (the log and Windows' records overlap).</summary>
    private static IEnumerable<WatchInterval> Merge(IEnumerable<WatchInterval> intervals)
    {
        foreach (var group in intervals.GroupBy(i => (i.Lane, i.Subject)))
        {
            WatchInterval? current = null;
            foreach (var i in group.OrderBy(i => i.StartUtc))
            {
                if (current is null) { current = i; continue; }
                if (i.StartUtc <= current.EndUtc + TimeSpan.FromSeconds(5))
                    current = current with { EndUtc = i.EndUtc > current.EndUtc ? i.EndUtc : current.EndUtc, Ongoing = current.Ongoing || i.Ongoing };
                else
                {
                    yield return current;
                    current = i;
                }
            }
            if (current is not null) yield return current;
        }
    }
}
