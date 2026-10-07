namespace Downpour.Contracts;

/// <summary>Privacy-sensitive capabilities Windows records per app (Settings &gt; Privacy &amp; security).</summary>
public static class WatchCapabilities
{
    public const string Camera = "webcam";
    public const string Microphone = "microphone";
    public const string ScreenCapture = "graphicsCaptureProgrammatic";
    public const string BorderlessScreenCapture = "graphicsCaptureWithoutBorder";
    public const string Location = "location";

    public static readonly IReadOnlyList<string> All = [Camera, Microphone, ScreenCapture, BorderlessScreenCapture, Location];

    public static string Label(string capability) => capability switch
    {
        Camera => "Camera",
        Microphone => "Microphone",
        ScreenCapture => "Screen capture",
        BorderlessScreenCapture => "Screen capture (no border)",
        Location => "Location",
        _ => capability,
    };
}

/// <summary>One app's most recent use of a capability, from Windows' own usage records.</summary>
public sealed record SensorUsage(string Capability, string App, string DisplayName, DateTimeOffset? LastStartUtc, DateTimeOffset? LastStopUtc, bool InUse);

/// <summary>A Windows session controlled from another computer (Remote Desktop and similar).</summary>
public sealed record RemoteSessionInfo(int SessionId, string State, string Protocol, string? ClientName, string? ClientAddress, bool IsCurrentSession);

/// <summary>A running program that can view or control this PC remotely.</summary>
public sealed record RemoteControlProcess(int ProcessId, string ProcessName, string Product, string Category);

/// <summary>Installed or running software that can monitor a person (keyloggers, spyware, employee or parental monitoring).</summary>
public sealed record MonitoringSoftware(string Name, string Product, string Category, string Severity, string Source);

/// <summary>One entry in the local watch log: when something started or stopped watching or controlling this PC.</summary>
public sealed record WatchEvent(DateTimeOffset TimeUtc, string Kind, string Subject, string Detail, string Severity);

public static class WatchEventKinds
{
    public const string SensorStarted = "sensor-started";
    public const string SensorStopped = "sensor-stopped";
    public const string RemoteSessionStarted = "remote-session-started";
    public const string RemoteSessionEnded = "remote-session-ended";
    public const string RemoteToolStarted = "remote-tool-started";
    public const string RemoteToolStopped = "remote-tool-stopped";
    public const string MonitoringSoftwareFound = "monitoring-software-found";
    public const string MonitoringSoftwareGone = "monitoring-software-gone";
}

public sealed record AntiStalkerSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<SensorUsage> SensorUsage,
    IReadOnlyList<RemoteSessionInfo> RemoteSessions,
    IReadOnlyList<RemoteControlProcess> RemoteControl,
    IReadOnlyList<MonitoringSoftware> Monitoring,
    IReadOnlyList<WatchEvent> Log,
    IReadOnlyList<string> Warnings);
