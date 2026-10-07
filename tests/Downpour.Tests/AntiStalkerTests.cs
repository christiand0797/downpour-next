using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class AntiStalkerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);

    private static AntiStalkerSnapshot Snapshot(DateTimeOffset at, SensorUsage[]? sensors = null, RemoteSessionInfo[]? sessions = null,
        RemoteControlProcess[]? tools = null, MonitoringSoftware[]? monitoring = null) =>
        new(1, at, sensors ?? [], sessions ?? [], tools ?? [], monitoring ?? [], [], []);

    [Theory]
    [InlineData("AnyDesk", "AnyDesk")]
    [InlineData("anydesk.exe", "AnyDesk")]
    [InlineData("remoting_host", "Chrome Remote Desktop")]
    [InlineData("QuickAssist", "Windows Quick Assist")]
    [InlineData("msra", "Windows Remote Assistance")]
    public void RecognizesRemoteControlPrograms(string processName, string product) =>
        Assert.Equal(product, AntiStalkerAnalyzer.MatchRemoteControl(1, processName)?.Product);

    [Theory]
    [InlineData("notepad")]
    [InlineData("explorer.exe")]
    [InlineData("anydeskhelper")]
    public void IgnoresOtherPrograms(string processName) => Assert.Null(AntiStalkerAnalyzer.MatchRemoteControl(1, processName));

    [Theory]
    [InlineData("Spyrix Free Keylogger", "Spyrix", "HIGH")]
    [InlineData("mSpy for Windows", "mSpy", "HIGH")]
    [InlineData("Teramind Agent", "Teramind", "MEDIUM")]
    [InlineData("Qustodio Parental Control", "Qustodio", "MEDIUM")]
    public void RecognizesMonitoringSoftware(string name, string product, string severity)
    {
        var match = AntiStalkerAnalyzer.MatchMonitoring(name, "installed program");
        Assert.Equal(product, match?.Product);
        Assert.Equal(severity, match?.Severity);
    }

    [Theory]
    [InlineData("mspyder toolkit")] // short tokens need a whole-word match
    [InlineData("Microsoft Edge")]
    [InlineData("")]
    public void DoesNotFlagOrdinaryPrograms(string name) => Assert.Null(AntiStalkerAnalyzer.MatchMonitoring(name, "installed program"));

    [Theory]
    [InlineData(@"C:#Program Files#Zoom#bin#Zoom.exe", "Zoom.exe")]
    [InlineData("Microsoft.WindowsCamera_8wekyb3d8bbwe", "Microsoft.WindowsCamera")]
    public void DisplayNamesAreReadable(string app, string expected) => Assert.Equal(expected, AntiStalkerAnalyzer.DisplayName(app));

    [Fact]
    public void FirstSampleProducesNoEvents() =>
        Assert.Empty(AntiStalkerAnalyzer.Diff(null, Snapshot(T0, [new SensorUsage(WatchCapabilities.Camera, "app", "app", T0, null, true)])));

    [Fact]
    public void CameraStartAndStopAreLogged()
    {
        var idle = Snapshot(T0, [new SensorUsage(WatchCapabilities.Camera, "zoom", "Zoom.exe", T0.AddDays(-1), T0.AddDays(-1), false)]);
        var active = Snapshot(T0.AddSeconds(10), [new SensorUsage(WatchCapabilities.Camera, "zoom", "Zoom.exe", T0.AddSeconds(5), null, true)]);
        var stopped = Snapshot(T0.AddSeconds(20), [new SensorUsage(WatchCapabilities.Camera, "zoom", "Zoom.exe", T0.AddSeconds(5), T0.AddSeconds(15), false)]);

        var started = Assert.Single(AntiStalkerAnalyzer.Diff(idle, active));
        Assert.Equal(WatchEventKinds.SensorStarted, started.Kind);
        Assert.Contains("Zoom.exe", started.Detail);
        Assert.Equal(T0.AddSeconds(5), started.TimeUtc);

        var ended = Assert.Single(AntiStalkerAnalyzer.Diff(active, stopped));
        Assert.Equal(WatchEventKinds.SensorStopped, ended.Kind);
    }

    [Fact]
    public void BriefUseBetweenSamplesIsStillLogged()
    {
        var before = Snapshot(T0, [new SensorUsage(WatchCapabilities.ScreenCapture, "spy", "spy.exe", T0.AddDays(-2), T0.AddDays(-2), false)]);
        var after = Snapshot(T0.AddSeconds(10), [new SensorUsage(WatchCapabilities.ScreenCapture, "spy", "spy.exe", T0.AddSeconds(3), T0.AddSeconds(4), false)]);
        var e = Assert.Single(AntiStalkerAnalyzer.Diff(before, after));
        Assert.Equal("MEDIUM", e.Severity); // screen capture by a non-Windows screenshot tool
    }

    [Fact]
    public void RemoteSessionAndToolTransitionsAreLoggedAndRaised()
    {
        var calm = Snapshot(T0);
        var watched = Snapshot(T0.AddSeconds(10),
            sessions: [new RemoteSessionInfo(3, "Active", "Remote Desktop (RDP)", "LAPTOP-X", "203.0.113.5", false)],
            tools: [new RemoteControlProcess(42, "anydesk.exe", "AnyDesk", "Remote support")]);
        var events = AntiStalkerAnalyzer.Diff(calm, watched);
        Assert.Contains(events, e => e.Kind == WatchEventKinds.RemoteSessionStarted && e.Severity == "HIGH" && e.Detail.Contains("LAPTOP-X") && e.Detail.Contains("203.0.113.5"));
        Assert.Contains(events, e => e.Kind == WatchEventKinds.RemoteToolStarted && e.Subject == "AnyDesk");

        var findings = AntiStalkerAnalyzer.Findings(watched);
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Source == SecurityFindingCatalog.AntiStalker);
        Assert.Contains(findings, f => f.Indicator == "anydesk.exe");

        var ended = AntiStalkerAnalyzer.Diff(watched, calm);
        Assert.Contains(ended, e => e.Kind == WatchEventKinds.RemoteSessionEnded);
        Assert.Contains(ended, e => e.Kind == WatchEventKinds.RemoteToolStopped);
    }

    [Fact]
    public void LiveCaptureIsValid()
    {
        var snapshot = new AntiStalkerProvider(new InstalledSoftwareInventoryProvider()).Capture([]);
        Assert.True(AntiStalkerClient.IsValid(snapshot));
    }

    [Fact]
    public async Task MonitorServesSnapshotsAndPersistsTheWatchLog()
    {
        var folder = Path.Combine(Path.GetTempPath(), "downpour_antistalker_" + Guid.NewGuid().ToString("N"));
        SecureJournalDirectory.Ensure(folder);
        try
        {
            var alerts = new SecurityAlertRepository(Path.Combine(folder, "alerts.db"));
            await alerts.InitializeAsync();
            var pipe = "Downpour.Test.AntiStalker." + Guid.NewGuid().ToString("N");
            var logPath = Path.Combine(folder, "watch-log.jsonl");
            using var monitor = new AntiStalkerMonitor(new AntiStalkerProvider(new InstalledSoftwareInventoryProvider()), alerts,
                NullLogger<AntiStalkerMonitor>.Instance, logPath, pipe);
            await monitor.StartAsync(CancellationToken.None);
            try
            {
                AntiStalkerSnapshot? snapshot = null;
                for (var i = 0; i < 40 && (snapshot is null || snapshot.Warnings.Contains("The first sample is still being collected.")); i++)
                {
                    snapshot = await new AntiStalkerClient(pipe).TryGetSnapshotAsync();
                    if (snapshot is null || snapshot.Warnings.Contains("The first sample is still being collected.")) await Task.Delay(250);
                }
                Assert.NotNull(snapshot);
                Assert.True(AntiStalkerClient.IsValid(snapshot));
            }
            finally
            {
                await monitor.StopAsync(CancellationToken.None);
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(folder, true); } catch (IOException) { }
        }
    }
}
