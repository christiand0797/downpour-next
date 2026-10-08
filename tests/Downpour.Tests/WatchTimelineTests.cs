using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class WatchTimelineTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 18, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Day = TimeSpan.FromHours(24);

    private static AntiStalkerSnapshot Snapshot(IReadOnlyList<SensorUsage>? usage = null, IReadOnlyList<WatchEvent>? log = null,
        IReadOnlyList<RemoteSessionInfo>? sessions = null, IReadOnlyList<RemoteControlProcess>? tools = null) =>
        new(1, Now, usage ?? [], sessions ?? [], tools ?? [], [], log ?? [], []);

    private static WatchEvent Event(DateTimeOffset at, string kind, string subject) => new(at, kind, subject, "detail", "LOW");

    [Fact]
    public void WindowsUsageRecordsBecomeIntervalsAndInUseIsOngoing()
    {
        var timeline = WatchTimeline.Build(Snapshot(usage:
        [
            new(WatchCapabilities.Camera, "app1", "Teams", Now.AddHours(-3), Now.AddHours(-2), false),
            new(WatchCapabilities.Microphone, "app2", "Zoom", Now.AddMinutes(-10), null, true),
            new(WatchCapabilities.BorderlessScreenCapture, "app3", "Recorder", Now.AddDays(-3), Now.AddDays(-3).AddHours(1), false),
        ]), Now, Day);

        Assert.Contains(timeline, i => i.Lane == WatchLanes.Camera && i.Subject == "Teams" && i.EndUtc == Now.AddHours(-2) && !i.Ongoing);
        Assert.Contains(timeline, i => i.Lane == WatchLanes.Microphone && i.Ongoing && i.EndUtc == Now);
        Assert.DoesNotContain(timeline, i => i.Lane == WatchLanes.Screen);
    }

    [Fact]
    public void WatchLogPairsMergeWithWindowsRecords()
    {
        var log = new[]
        {
            Event(Now.AddHours(-5), WatchEventKinds.SensorStarted, "Camera · Teams"),
            Event(Now.AddHours(-4), WatchEventKinds.SensorStopped, "Camera · Teams"),
            Event(Now.AddHours(-1), WatchEventKinds.RemoteToolStarted, "AnyDesk"),
            Event(Now.AddMinutes(-30), WatchEventKinds.RemoteToolStopped, "AnyDesk"),
        };
        var usage = new SensorUsage[] { new(WatchCapabilities.Camera, "a", "Teams", Now.AddHours(-4).AddMinutes(-30), Now.AddHours(-3), false) };
        var timeline = WatchTimeline.Build(Snapshot(usage, log), Now, Day);

        var camera = Assert.Single(timeline, i => i.Lane == WatchLanes.Camera);
        Assert.Equal(Now.AddHours(-5), camera.StartUtc);
        Assert.Equal(Now.AddHours(-3), camera.EndUtc);
        var remote = Assert.Single(timeline, i => i.Lane == WatchLanes.Remote);
        Assert.Equal("AnyDesk", remote.Subject);
        Assert.Equal(TimeSpan.FromMinutes(30), remote.EndUtc - remote.StartUtc);
    }

    [Fact]
    public void UnmatchedStartIsOngoingOnlyWhenConfirmedActive()
    {
        var log = new[]
        {
            Event(Now.AddHours(-2), WatchEventKinds.RemoteSessionStarted, "Remote session 3"),
            Event(Now.AddHours(-6), WatchEventKinds.SensorStarted, "Microphone · Unknown app"),
        };
        var timeline = WatchTimeline.Build(Snapshot(log: log, sessions: [new(3, "Active", "RDP", "LAPTOP", "10.0.0.9", false)]), Now, Day);

        var session = Assert.Single(timeline, i => i.Lane == WatchLanes.Remote);
        Assert.True(session.Ongoing);
        Assert.Equal(Now, session.EndUtc);
        var mic = Assert.Single(timeline, i => i.Lane == WatchLanes.Microphone);
        Assert.False(mic.Ongoing);
        Assert.Equal(TimeSpan.FromMinutes(1), mic.EndUtc - mic.StartUtc);
    }

    [Fact]
    public void StopWithoutStartBeginsAtTheWindowEdgeAndEverythingIsClipped()
    {
        var log = new[] { Event(Now.AddHours(-3), WatchEventKinds.SensorStopped, "Location · Maps") };
        var timeline = WatchTimeline.Build(Snapshot(log: log, usage: [new(WatchCapabilities.Camera, "a", "Old", Now.AddDays(-2), Now.AddHours(-20), false)]), Now, Day);
        Assert.Contains(timeline, i => i.Lane == WatchLanes.Location && i.StartUtc == Now - Day);
        Assert.Contains(timeline, i => i.Lane == WatchLanes.Camera && i.StartUtc == Now - Day && i.EndUtc == Now.AddHours(-20));
        Assert.All(timeline, i => Assert.True(i.StartUtc >= Now - Day && i.EndUtc <= Now));
    }
}
