namespace Downpour.Contracts;

/// <summary>Audio endpoint direction, as Windows Core Audio reports it.</summary>
public static class AudioFlows
{
    public const string Playback = "playback";
    public const string Recording = "recording";
}

/// <summary>What kind of hardware or software an audio endpoint is.</summary>
public static class AudioDeviceKinds
{
    public const string BuiltIn = "built-in";
    public const string Usb = "usb";
    public const string Bluetooth = "bluetooth";
    public const string Hdmi = "hdmi";
    public const string Virtual = "virtual";
    public const string Loopback = "loopback";
    public const string Network = "network";
    public const string Other = "other";
}

public static class AudioIssueCategories
{
    /// <summary>Something is recording from a microphone or loopback device.</summary>
    public const string Listening = "Listening";
    /// <summary>Audio devices appearing, loopback or virtual capture devices.</summary>
    public const string Device = "Device";
    /// <summary>Audio effect DLLs (APOs) and the audio engine process.</summary>
    public const string Driver = "Driver";
    /// <summary>Things that make sound drop out, crackle, or stop.</summary>
    public const string Glitch = "Glitch";
    /// <summary>Microphone privacy settings.</summary>
    public const string Privacy = "Privacy";
}

/// <summary>One audio endpoint (speaker, headset, microphone, virtual cable...). Peak is the live level, 0..1.</summary>
public sealed record AudioDevice(
    string Id,
    string Name,
    string Adapter,
    string Flow,
    string State,
    string Kind,
    bool IsDefault,
    string? Format,
    int? VolumePercent,
    bool? Muted,
    double Peak,
    bool IsNew,
    DateTimeOffset? FirstSeenUtc);

/// <summary>
/// One program's audio stream on an endpoint. For recording endpoints an active session means the program is
/// receiving microphone (or loopback) audio right now. Only levels are read, never audio content.
/// </summary>
public sealed record AudioSession(
    string Flow,
    string Device,
    string DeviceKind,
    int ProcessId,
    string ProcessName,
    string? Path,
    string State,
    double Peak,
    bool HasWindow,
    bool? Signed,
    string? Signer);

/// <summary>An Audio Processing Object (effect DLL) registered with the audio engine and loaded into audiodg.exe.</summary>
public sealed record AudioEffect(string Clsid, string Name, string? DllPath, bool? Signed, string? Signer, bool Microsoft);

public sealed record AudioPosture(
    bool? MicrophoneAccessAllowed,
    bool? DesktopAppsMicrophoneAllowed,
    string AudioService,
    string EndpointBuilder,
    double AudioEngineCpuPercent,
    string? AudioEnginePath,
    bool? AudioEngineSigned,
    int AudioEngineInstances,
    int AudioErrors24h,
    int AudioWarnings24h);

/// <summary>A threat, privacy exposure, or glitch cause found on the Audio page. Severity INFO is display-only.</summary>
public sealed record AudioIssue(string Severity, string Category, string Title, string Detail, string Technique, string Indicator);

public sealed record AudioSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<AudioDevice> Devices,
    IReadOnlyList<AudioSession> Sessions,
    IReadOnlyList<AudioEffect> Effects,
    AudioPosture Posture,
    IReadOnlyList<AudioIssue> Issues,
    IReadOnlyList<string> Warnings);
