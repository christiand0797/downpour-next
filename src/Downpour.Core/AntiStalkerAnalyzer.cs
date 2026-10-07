using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Anti-stalker analysis (DN-030): which programs can watch or control this PC, and what changed between two samples.
/// Pure logic so it can be tested without the registry, sessions, or processes.
/// </summary>
public static class AntiStalkerAnalyzer
{
    /// <summary>Programs that let someone view or control this PC from elsewhere. Keys are process names (lower case, with .exe).</summary>
    public static readonly IReadOnlyDictionary<string, (string Product, string Category)> RemoteControlProcesses =
        new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase)
        {
            ["teamviewer.exe"] = ("TeamViewer", "Remote support"),
            ["teamviewer_service.exe"] = ("TeamViewer", "Remote support"),
            ["anydesk.exe"] = ("AnyDesk", "Remote support"),
            ["rustdesk.exe"] = ("RustDesk", "Remote support"),
            ["screenconnect.clientservice.exe"] = ("ConnectWise ScreenConnect", "Remote support"),
            ["screenconnect.windowsclient.exe"] = ("ConnectWise ScreenConnect", "Remote support"),
            ["srservice.exe"] = ("Splashtop", "Remote support"),
            ["strwinclt.exe"] = ("Splashtop", "Remote support"),
            ["remoting_host.exe"] = ("Chrome Remote Desktop", "Remote desktop"),
            ["quickassist.exe"] = ("Windows Quick Assist", "Remote support"),
            ["msra.exe"] = ("Windows Remote Assistance", "Remote support"),
            ["rdpsa.exe"] = ("Windows Remote Assistance", "Remote support"),
            ["parsecd.exe"] = ("Parsec", "Remote desktop"),
            ["winvnc.exe"] = ("VNC server", "Remote desktop"),
            ["tvnserver.exe"] = ("TightVNC server", "Remote desktop"),
            ["vncserver.exe"] = ("VNC server", "Remote desktop"),
            ["uvnc_service.exe"] = ("UltraVNC server", "Remote desktop"),
            ["logmein.exe"] = ("LogMeIn", "Remote support"),
            ["lmiguardiansvc.exe"] = ("LogMeIn", "Remote support"),
            ["g2ax_comm_expert.exe"] = ("GoTo Assist", "Remote support"),
            ["za_connect.exe"] = ("Zoho Assist", "Remote support"),
            ["remotepcservice.exe"] = ("RemotePC", "Remote support"),
            ["dwagent.exe"] = ("DWService", "Remote support"),
            ["supremo.exe"] = ("Supremo", "Remote support"),
            ["aeroadmin.exe"] = ("AeroAdmin", "Remote support"),
            ["ammyy_admin.exe"] = ("Ammyy Admin", "Remote support"),
            ["rserver3.exe"] = ("Radmin server", "Remote support"),
            ["client32.exe"] = ("NetSupport Manager client", "Remote support"),
            ["meshagent.exe"] = ("MeshCentral agent", "Remote management"),
            ["ateraagent.exe"] = ("Atera agent", "Remote management"),
            ["tacticalrmm.exe"] = ("Tactical RMM agent", "Remote management"),
            ["remcos.exe"] = ("Remcos", "Remote access trojan"),
            ["njrat.exe"] = ("njRAT", "Remote access trojan"),
            ["darkcomet.exe"] = ("DarkComet", "Remote access trojan"),
            ["quasar.exe"] = ("Quasar RAT", "Remote access trojan"),
        };

    /// <summary>
    /// Monitoring software matched by installed-program name or process name (case-insensitive substring of the
    /// installed name; exact match of the process name). Categories: Spyware/keylogger (HIGH), Employee monitoring and
    /// Parental control (MEDIUM: legitimate uses exist, but each can watch a person without them noticing).
    /// </summary>
    public static readonly IReadOnlyList<(string Match, string Product, string Category, string Severity)> MonitoringCatalog =
    [
        ("spyrix", "Spyrix", "Spyware / keylogger", "HIGH"),
        ("refog", "Refog", "Spyware / keylogger", "HIGH"),
        ("kidlogger", "KidLogger", "Spyware / keylogger", "HIGH"),
        ("hoverwatch", "Hoverwatch", "Spyware / keylogger", "HIGH"),
        ("spyagent", "SpyAgent", "Spyware / keylogger", "HIGH"),
        ("revealer keylogger", "Revealer Keylogger", "Spyware / keylogger", "HIGH"),
        ("ardamax", "Ardamax Keylogger", "Spyware / keylogger", "HIGH"),
        ("elite keylogger", "Elite Keylogger", "Spyware / keylogger", "HIGH"),
        ("actual keylogger", "Actual Keylogger", "Spyware / keylogger", "HIGH"),
        ("best free keylogger", "Best Free Keylogger", "Spyware / keylogger", "HIGH"),
        ("win-spy", "Win-Spy", "Spyware / keylogger", "HIGH"),
        ("pctattletale", "pcTattletale", "Spyware / keylogger", "HIGH"),
        ("flexispy", "FlexiSPY", "Spyware / keylogger", "HIGH"),
        ("mspy", "mSpy", "Spyware / keylogger", "HIGH"),
        ("webwatcher", "WebWatcher", "Spyware / keylogger", "HIGH"),
        ("realtime-spy", "Realtime-Spy", "Spyware / keylogger", "HIGH"),
        ("softactivity", "SoftActivity", "Employee monitoring", "MEDIUM"),
        ("teramind", "Teramind", "Employee monitoring", "MEDIUM"),
        ("activtrak", "ActivTrak", "Employee monitoring", "MEDIUM"),
        ("hubstaff", "Hubstaff", "Employee monitoring", "MEDIUM"),
        ("interguard", "InterGuard", "Employee monitoring", "MEDIUM"),
        ("veriato", "Veriato", "Employee monitoring", "MEDIUM"),
        ("staffcop", "StaffCop", "Employee monitoring", "MEDIUM"),
        ("kickidler", "Kickidler", "Employee monitoring", "MEDIUM"),
        ("clever control", "Clever Control", "Employee monitoring", "MEDIUM"),
        ("browsereporter", "CurrentWare BrowseReporter", "Employee monitoring", "MEDIUM"),
        ("time doctor", "Time Doctor", "Employee monitoring", "MEDIUM"),
        ("insightful", "Insightful (Workpuls)", "Employee monitoring", "MEDIUM"),
        ("controlio", "Controlio", "Employee monitoring", "MEDIUM"),
        ("qustodio", "Qustodio", "Parental control", "MEDIUM"),
        ("net nanny", "Net Nanny", "Parental control", "MEDIUM"),
        ("norton family", "Norton Family", "Parental control", "MEDIUM"),
        ("kaspersky safe kids", "Kaspersky Safe Kids", "Parental control", "MEDIUM"),
        ("netsupport school", "NetSupport School", "Classroom monitoring", "MEDIUM"),
    ];

    /// <summary>Windows components whose screen captures are user-initiated (screenshots), not someone watching.</summary>
    private static readonly string[] UserScreenshotApps = ["Microsoft.ScreenSketch_", "Microsoft.Windows.SnippingTool", "MicrosoftWindows.Client.CBS_"];

    public static RemoteControlProcess? MatchRemoteControl(int processId, string processName)
    {
        var name = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? processName : processName + ".exe";
        return RemoteControlProcesses.TryGetValue(name, out var match) ? new RemoteControlProcess(processId, name, match.Product, match.Category) : null;
    }

    public static MonitoringSoftware? MatchMonitoring(string name, string source)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var lower = name.ToLowerInvariant();
        foreach (var (match, product, category, severity) in MonitoringCatalog)
        {
            // Short tokens (mspy) must match a whole word so "mspyder" or similar names do not trip them.
            var index = lower.IndexOf(match, StringComparison.Ordinal);
            if (index < 0) continue;
            var before = index == 0 || !char.IsLetterOrDigit(lower[index - 1]);
            var after = index + match.Length >= lower.Length || !char.IsLetterOrDigit(lower[index + match.Length]);
            if (match.Length >= 6 || (before && after)) return new MonitoringSoftware(name, product, category, severity, source);
        }
        return null;
    }

    /// <summary>Readable name for a consent-store key: packaged family names stay as-is; desktop app paths use '#' for '\'.</summary>
    public static string DisplayName(string app)
    {
        if (app.Contains('#'))
        {
            var path = app.Replace('#', '\\');
            var file = path[(path.LastIndexOf('\\') + 1)..];
            return file.Length > 0 ? file : path;
        }
        var underscore = app.IndexOf('_');
        return underscore > 0 ? app[..underscore] : app;
    }

    public static bool IsUserScreenshotApp(string app) =>
        UserScreenshotApps.Any(prefix => app.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    /// <summary>What started or stopped between two samples. The first sample (previous == null) produces no events.</summary>
    public static IReadOnlyList<WatchEvent> Diff(AntiStalkerSnapshot? previous, AntiStalkerSnapshot current)
    {
        if (previous is null) return [];
        var events = new List<WatchEvent>();
        var now = current.CapturedAtUtc;

        var before = previous.SensorUsage.ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
        foreach (var usage in current.SensorUsage)
        {
            before.TryGetValue(Key(usage), out var old);
            var label = WatchCapabilities.Label(usage.Capability);
            // A new use since the last sample: either it is in use now and was not before, or it started and stopped in between.
            var startedSinceLastSample = usage.LastStartUtc is { } start && (old?.LastStartUtc is not { } oldStart || start > oldStart);
            if ((usage.InUse && old?.InUse != true) || (startedSinceLastSample && !usage.InUse))
                events.Add(new WatchEvent(usage.LastStartUtc ?? now, WatchEventKinds.SensorStarted, $"{label} · {usage.DisplayName}",
                    usage.InUse ? $"{usage.DisplayName} started using the {label.ToLowerInvariant()}." : $"{usage.DisplayName} used the {label.ToLowerInvariant()} briefly.",
                    SensorSeverity(usage)));
            if (old?.InUse == true && !usage.InUse)
                events.Add(new WatchEvent(usage.LastStopUtc ?? now, WatchEventKinds.SensorStopped, $"{label} · {usage.DisplayName}",
                    $"{usage.DisplayName} stopped using the {label.ToLowerInvariant()}.", "LOW"));
        }

        Compare(previous.RemoteSessions.Where(s => s.State == "Active").Select(s => s.SessionId.ToString()),
            current.RemoteSessions.Where(s => s.State == "Active").Select(s => s.SessionId.ToString()),
            id => current.RemoteSessions.FirstOrDefault(s => s.SessionId.ToString() == id),
            id => previous.RemoteSessions.FirstOrDefault(s => s.SessionId.ToString() == id),
            (session, started) => started
                ? new WatchEvent(now, WatchEventKinds.RemoteSessionStarted, $"Remote session {session!.SessionId}",
                    $"A {session.Protocol} session is controlling this PC{(session.ClientName is { Length: > 0 } client ? $" from \"{client}\"" : "")}{(session.ClientAddress is { Length: > 0 } address ? $" ({address})" : "")}.", "HIGH")
                : new WatchEvent(now, WatchEventKinds.RemoteSessionEnded, $"Remote session {session!.SessionId}", $"The {session.Protocol} session ended.", "LOW"),
            events);

        Compare(previous.RemoteControl.Select(p => p.ProcessName), current.RemoteControl.Select(p => p.ProcessName),
            name => current.RemoteControl.FirstOrDefault(p => p.ProcessName == name),
            name => previous.RemoteControl.FirstOrDefault(p => p.ProcessName == name),
            (tool, started) => new WatchEvent(now, started ? WatchEventKinds.RemoteToolStarted : WatchEventKinds.RemoteToolStopped, tool!.Product,
                started ? $"{tool.Product} ({tool.ProcessName}) started. It can let someone view or control this PC." : $"{tool.Product} stopped.",
                started ? (tool.Category == "Remote access trojan" ? "CRITICAL" : "MEDIUM") : "LOW"),
            events);

        Compare(previous.Monitoring.Select(m => m.Product), current.Monitoring.Select(m => m.Product),
            product => current.Monitoring.FirstOrDefault(m => m.Product == product),
            product => previous.Monitoring.FirstOrDefault(m => m.Product == product),
            (software, found) => new WatchEvent(now, found ? WatchEventKinds.MonitoringSoftwareFound : WatchEventKinds.MonitoringSoftwareGone, software!.Product,
                found ? $"{software.Category} software found: {software.Name} ({software.Source})." : $"{software.Product} is no longer present.",
                found ? software.Severity : "LOW"),
            events);

        return events.OrderBy(e => e.TimeUtc).ToArray();
    }

    private static string Key(SensorUsage usage) => usage.Capability + "|" + usage.App;

    private static string SensorSeverity(SensorUsage usage) => usage.Capability switch
    {
        WatchCapabilities.ScreenCapture or WatchCapabilities.BorderlessScreenCapture => IsUserScreenshotApp(usage.App) ? "LOW" : "MEDIUM",
        WatchCapabilities.Camera or WatchCapabilities.Microphone => "MEDIUM",
        _ => "LOW",
    };

    private static void Compare<T>(IEnumerable<string> before, IEnumerable<string> after, Func<string, T?> currentItem, Func<string, T?> previousItem,
        Func<T?, bool, WatchEvent> create, List<WatchEvent> events)
    {
        var old = before.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var now = after.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var added in now.Except(old, StringComparer.OrdinalIgnoreCase)) events.Add(create(currentItem(added), true));
        foreach (var removed in old.Except(now, StringComparer.OrdinalIgnoreCase)) events.Add(create(previousItem(removed), false));
    }

    /// <summary>Triage findings for things that can watch or control the PC right now.</summary>
    public static IReadOnlyList<SecurityFindingObservation> Findings(AntiStalkerSnapshot snapshot)
    {
        var findings = new List<SecurityFindingObservation>();
        foreach (var session in snapshot.RemoteSessions.Where(s => s.State == "Active"))
            findings.Add(SecurityFindingMapper.Create(SecurityFindingCatalog.AntiStalker, "Remote session", "HIGH", "T1021.001",
                $"Someone is controlling this PC through a {session.Protocol} session{(session.ClientName is { Length: > 0 } c ? $" from {c}" : "")}", $"session-{session.SessionId}"));
        foreach (var tool in snapshot.RemoteControl.DistinctBy(t => t.Product))
            findings.Add(SecurityFindingMapper.Create(SecurityFindingCatalog.AntiStalker, "Remote-control software running",
                tool.Category == "Remote access trojan" ? "CRITICAL" : "MEDIUM", "T1219", $"{tool.Product} is running and can let someone view or control this PC", tool.ProcessName));
        foreach (var software in snapshot.Monitoring.DistinctBy(m => m.Product))
            findings.Add(SecurityFindingMapper.Create(SecurityFindingCatalog.AntiStalker, "Monitoring software", software.Severity, "T1056.001",
                $"{software.Category} software is present: {software.Product}", software.Product));
        return findings;
    }
}
