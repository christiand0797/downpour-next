using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Stored first-seen times for audio endpoints, keyed by a hash of the endpoint ID.</summary>
public sealed record AudioDeviceBaseline(int SchemaVersion, DateTimeOffset CreatedAtUtc, IReadOnlyDictionary<string, DateTimeOffset?> Devices);

/// <summary>
/// Audio Shield rules (not in v29). Classifies audio endpoints, decides which microphone listeners are expected, and
/// turns devices, capture sessions, audio effect DLLs and engine posture into threats, privacy notes and glitch
/// causes. Only levels and metadata are used; audio content is never read.
/// </summary>
public static partial class AudioThreatAnalyzer
{
    public const string Info = "INFO";
    public const int MaximumDevices = 128;
    public const int MaximumSessions = 256;
    public const int MaximumEffects = 256;
    public static readonly TimeSpan NewDeviceWindow = TimeSpan.FromDays(7);
    public const double EngineCpuGlitchPercent = 15;

    /// <summary>Programs that routinely use the microphone (calls, browsers, recording, streaming, voice features).</summary>
    public static readonly IReadOnlySet<string> ExpectedListeners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "teams", "ms-teams", "msteams", "zoom", "cpthost", "discord", "discordptb", "discordcanary", "slack", "skype",
        "webex", "ciscowebexstart", "ciscocollabhost", "atmgr", "gotomeeting", "g2mcomm", "ringcentral", "whatsapp",
        "telegram", "signal", "viber", "element", "mumble", "teamspeak", "ts3client_win64", "ventrilo",
        "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera", "opera_gx", "vivaldi", "arc", "librewolf", "waterfox",
        "obs64", "obs32", "obs", "streamlabs obs", "streamlabs", "xsplit.core", "audacity", "reaper", "fl64", "ableton live 12 suite",
        "ableton live 11 suite", "studio one", "cubase13", "bandlab", "voicemeeter", "voicemeeterpro", "voicemeeter8", "voicemeeter8x64",
        "nvidia broadcast", "nvidia broadcast ui", "krisp", "sonar", "steelseriesgg", "steelseriessonar", "ghub", "icue",
        "steam", "steamwebhelper", "gamebar", "gamebarftserver", "xboxpcapp", "xboxapp", "nvcontainer", "nvidia share",
        "voiceaccess", "searchhost", "cortana", "speechruntime", "speechmodeldownload", "narrator", "soundrecorder", "voicerecorder",
        "windowscamera", "phoneexperiencehost", "yourphone", "mmsys", "rundll32", "sndvol", "systemsettings", "applicationframehost",
        "downpour.desktop", "downpour.service",
    };

    private static readonly string[] LoopbackMarkers = ["stereo mix", "what u hear", "wave out mix", "loopback", "what you hear", "rec. playback"];

    private static readonly string[] VirtualMarkers =
    [
        "vb-audio", "cable output", "cable input", "voicemeeter", "virtual audio cable", "virtual cable", "nvidia broadcast", "krisp",
        "steam streaming", "obs virtual", "elgato virtual", "sonar -", "steelseries sonar", "virtual", "line 1", "hi-fi cable",
        "blackhole", "soundflower", "voicemod", "clownfish", "camo", "droidcam", "iriun", "nahimic mirroring", "mirroring device",
    ];

    private static readonly string[] BluetoothMarkers = ["bluetooth", "hands-free", "handsfree", "airpods", "buds", "bose", "wh-1000", "jabra", "headset ag"];

    private static readonly string[] HdmiMarkers = ["hdmi", "displayport", "display audio", "nvidia high definition audio", "amd high definition audio"];

    /// <summary>Classifies an endpoint from its names, PnP enumerator and Core Audio form factor.</summary>
    public static string ClassifyKind(string name, string adapter, string? enumerator, int? formFactor)
    {
        var text = $"{name} {adapter}".ToLowerInvariant();
        var bus = (enumerator ?? "").ToUpperInvariant();
        if (LoopbackMarkers.Any(text.Contains)) return AudioDeviceKinds.Loopback;
        if (formFactor == 0 || text.Contains("remote audio")) return AudioDeviceKinds.Network;
        if (bus.StartsWith("BTH", StringComparison.Ordinal) || BluetoothMarkers.Any(text.Contains)) return AudioDeviceKinds.Bluetooth;
        if (VirtualMarkers.Any(text.Contains) || bus is "ROOT") return AudioDeviceKinds.Virtual;
        if (formFactor == 9 || HdmiMarkers.Any(text.Contains)) return AudioDeviceKinds.Hdmi;
        if (bus == "USB" || text.Contains("usb")) return AudioDeviceKinds.Usb;
        if (bus is "HDAUDIO" or "INTELAUDIO" or "ACPI" or "PCI" || text.Contains("realtek") || text.Contains("high definition audio")
            || text.Contains("smart sound") || text.Contains("conexant") || text.Contains("cirrus")) return AudioDeviceKinds.BuiltIn;
        return AudioDeviceKinds.Other;
    }

    /// <summary>"48 kHz, 24-bit, 2 ch" from a WAVEFORMATEX (or WAVEFORMATEXTENSIBLE) blob; null when it is not one.</summary>
    public static string? DescribeFormat(ReadOnlySpan<byte> waveFormat)
    {
        if (waveFormat.Length < 16) return null;
        var channels = BitConverter.ToUInt16(waveFormat[2..4]);
        var rate = BitConverter.ToUInt32(waveFormat[4..8]);
        var bits = BitConverter.ToUInt16(waveFormat[14..16]);
        if (channels is 0 or > 32 || rate is < 1000 or > 1_536_000 || bits is 0 or > 64) return null;
        if (waveFormat.Length >= 24 && BitConverter.ToUInt16(waveFormat[0..2]) == 0xFFFE && BitConverter.ToUInt16(waveFormat[18..20]) is > 0 and <= 64 and var valid)
            bits = valid;
        var khz = rate % 1000 == 0 ? $"{rate / 1000}" : $"{rate / 1000.0:0.#}";
        return $"{khz} kHz, {bits}-bit, {channels} ch";
    }

    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..32];

    /// <summary>
    /// Marks endpoints first seen within <see cref="NewDeviceWindow"/>. The first run is trust-on-first-use, so nothing
    /// present then is new. The baseline stores endpoint ID hashes only.
    /// </summary>
    public static (IReadOnlyList<AudioDevice> Devices, AudioDeviceBaseline Baseline) MarkNew(IReadOnlyList<AudioDevice> devices, AudioDeviceBaseline? baseline, DateTimeOffset now)
    {
        var known = baseline?.Devices ?? new Dictionary<string, DateTimeOffset?>();
        var updated = new Dictionary<string, DateTimeOffset?>(known, StringComparer.Ordinal);
        var marked = new List<AudioDevice>(devices.Count);
        foreach (var device in devices)
        {
            var key = Hash(device.Id);
            if (!updated.TryGetValue(key, out var firstSeen))
            {
                firstSeen = baseline is null ? null : now;
                if (updated.Count < 4096) updated[key] = firstSeen;
            }
            var isNew = firstSeen is { } seen && now - seen <= NewDeviceWindow;
            marked.Add(device with { IsNew = isNew, FirstSeenUtc = firstSeen });
        }
        return (marked, new AudioDeviceBaseline(1, baseline?.CreatedAtUtc ?? now, updated));
    }

    public static bool IsExpectedListener(string processName) =>
        ExpectedListeners.Contains(processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? processName[..^4] : processName);

    public static bool IsUserWritable(string? path) => path is not null && UserWritablePath().IsMatch(path);

    /// <summary>Turns the current audio state into threats, privacy notes and glitch causes, most severe first.</summary>
    public static IReadOnlyList<AudioIssue> Assess(IReadOnlyList<AudioDevice> devices, IReadOnlyList<AudioSession> sessions,
        IReadOnlyList<AudioEffect> effects, AudioPosture posture)
    {
        var issues = new List<AudioIssue>();
        AssessListeners(sessions, issues);
        AssessEffects(effects, issues);
        AssessEngine(posture, issues);
        AssessDevices(devices, issues);
        return issues
            .DistinctBy(issue => (issue.Category, issue.Indicator))
            .OrderBy(issue => Rank(issue.Severity))
            .ThenBy(issue => issue.Category, StringComparer.Ordinal)
            .Take(128)
            .ToArray();
    }

    private static void AssessListeners(IReadOnlyList<AudioSession> sessions, List<AudioIssue> issues)
    {
        foreach (var session in sessions.Where(s => s.Flow == AudioFlows.Recording && s.State == "active" && s.ProcessId > 0))
        {
            var who = session.ProcessName;
            var where = session.Path ?? "path unavailable";
            var indicator = $"listen|{who.ToLowerInvariant()}|{(session.Path ?? "").ToLowerInvariant()}";
            var expected = IsExpectedListener(who);
            var detail = $"{who} (PID {session.ProcessId}) is receiving audio from {session.Device}. Program: {where}.";
            if (AntiStalkerAnalyzer.MatchMonitoring(who, "running process") is { } spy)
                issues.Add(new("HIGH", AudioIssueCategories.Listening, $"Monitoring software is listening: {spy.Product}", detail, "T1123", indicator));
            else if (AntiStalkerAnalyzer.MatchRemoteControl(session.ProcessId, who) is { } remote)
                issues.Add(new("HIGH", AudioIssueCategories.Listening, $"Remote-control tool is listening: {remote.Product}", detail, "T1123", indicator));
            else if (session.Signed == false)
                issues.Add(new("HIGH", AudioIssueCategories.Listening, $"Unsigned program is listening: {who}",
                    detail + " The program is not validly signed, so its publisher cannot be confirmed.", "T1123", indicator));
            else if (session.DeviceKind == AudioDeviceKinds.Loopback && !expected)
                issues.Add(new("MEDIUM", AudioIssueCategories.Listening, $"{who} is recording everything you hear",
                    detail + " The device is a loopback (Stereo Mix) input that captures all sound this PC plays.", "T1123", indicator));
            else if (!expected && IsUserWritable(session.Path))
                issues.Add(new("MEDIUM", AudioIssueCategories.Listening, $"Program in a user folder is listening: {who}",
                    detail + $" Signed by {PersistenceAnalyzer.SignerDisplay(session.Signer)}, but it runs from a folder any program can write to.", "T1123", indicator));
            else if (!expected && !session.HasWindow)
                issues.Add(new("MEDIUM", AudioIssueCategories.Listening, $"Background program with no window is listening: {who}",
                    detail + " Nothing on screen shows that it is recording.", "T1123", indicator));
            else
                issues.Add(new(Info, AudioIssueCategories.Listening, $"{who} is using the microphone", detail, "T1123", indicator));
        }
    }

    private static void AssessEffects(IReadOnlyList<AudioEffect> effects, List<AudioIssue> issues)
    {
        foreach (var effect in effects)
        {
            var indicator = $"apo|{effect.Clsid.ToLowerInvariant()}|{(effect.DllPath ?? "").ToLowerInvariant()}";
            if (effect.DllPath is null)
                issues.Add(new(Info, AudioIssueCategories.Glitch, $"Audio effect registration is broken: {effect.Name}",
                    "The effect is registered with the audio engine but its DLL could not be found; reinstalling the audio driver usually fixes this.", "Posture", indicator));
            else if (IsUserWritable(effect.DllPath))
                issues.Add(new("HIGH", AudioIssueCategories.Driver, $"Audio effect loads from a user-writable folder: {effect.Name}",
                    $"{effect.DllPath} is loaded into the audio engine (audiodg.exe), which hears all audio. Legitimate effects install under Program Files or Windows.", "T1546.015", indicator));
            else if (effect.Signed == false)
                issues.Add(new("HIGH", AudioIssueCategories.Driver, $"Unsigned audio effect DLL: {effect.Name}",
                    $"{effect.DllPath} is not validly signed but is loaded into the audio engine, which hears all audio.", "T1546.015", indicator));
        }
    }

    private static void AssessEngine(AudioPosture posture, List<AudioIssue> issues)
    {
        if (posture.AudioEnginePath is { } engine && !engine.EndsWith(@"\System32\audiodg.exe", StringComparison.OrdinalIgnoreCase))
            issues.Add(new("CRITICAL", AudioIssueCategories.Driver, "audiodg.exe is running from an unexpected folder",
                $"The Windows audio engine always runs from System32; this copy runs from {engine}.", "T1036.005", $"engine-path|{engine.ToLowerInvariant()}"));
        if (posture.AudioEngineSigned == false)
            issues.Add(new("CRITICAL", AudioIssueCategories.Driver, "audiodg.exe is not signed by Microsoft",
                "The running audio engine failed the Microsoft signature check.", "T1036.005", "engine-signature"));
        foreach (var (name, state) in new[] { ("Windows Audio", posture.AudioService), ("Windows Audio Endpoint Builder", posture.EndpointBuilder) })
        {
            if (state is "Running" or "Unknown" or "StartPending") continue;
            issues.Add(new("HIGH", AudioIssueCategories.Glitch, $"{name} service is {state.ToLowerInvariant()}",
                "No sound can play or be recorded until it runs. Stopping it is also a way to disable audio alerts.", "T1489", $"service|{name}"));
        }
        if (posture.AudioEngineCpuPercent >= EngineCpuGlitchPercent)
            issues.Add(new("MEDIUM", AudioIssueCategories.Glitch, $"Audio engine is using {posture.AudioEngineCpuPercent:0}% CPU",
                "Heavy audio effects or enhancements make sound crackle, stutter, or drop out. Try turning off audio enhancements for the device.", "Posture", "engine-cpu"));
        if (posture.AudioErrors24h > 0)
            issues.Add(new(Info, AudioIssueCategories.Glitch, $"{posture.AudioErrors24h} audio errors in the last 24 hours",
                "Windows logged audio errors (Microsoft-Windows-Audio). Repeated errors often accompany dropouts or devices disappearing.", "Posture", "audio-errors"));
        if (posture.MicrophoneAccessAllowed == false)
            issues.Add(new(Info, AudioIssueCategories.Privacy, "Microphone access is off for apps",
                "Windows blocks apps from using the microphone (Settings > Privacy & security > Microphone).", "Posture", "mic-access-off"));
        else if (posture.DesktopAppsMicrophoneAllowed == true)
            issues.Add(new(Info, AudioIssueCategories.Privacy, "Desktop apps may use the microphone",
                "Classic desktop programs can open the microphone without asking each time; the Listening list shows who is using it.", "Posture", "desktop-mic-allowed"));
    }

    private static void AssessDevices(IReadOnlyList<AudioDevice> devices, List<AudioIssue> issues)
    {
        var active = devices.Where(d => d.State == "active").ToArray();
        if (devices.Count > 0 && !active.Any(d => d.Flow == AudioFlows.Playback))
            issues.Add(new("MEDIUM", AudioIssueCategories.Glitch, "No playback device is active",
                "Nothing can play sound. Check that speakers or headphones are connected and enabled in Sound settings.", "Posture", "no-playback"));
        foreach (var device in active)
        {
            var key = $"device|{Hash(device.Id).ToLowerInvariant()}";
            if (device.Flow == AudioFlows.Recording && device.IsNew)
                issues.Add(new("MEDIUM", AudioIssueCategories.Device, $"New microphone appeared: {device.Name}",
                    $"A {device.Kind} recording device first appeared {device.FirstSeenUtc:yyyy-MM-dd HH:mm} UTC. If you did not connect it, check paired Bluetooth devices and installed virtual audio software.",
                    "T1123", key + "|new"));
            if (device.Flow == AudioFlows.Recording && device.Kind == AudioDeviceKinds.Loopback)
                issues.Add(new("LOW", AudioIssueCategories.Device, $"Loopback recording is enabled: {device.Name}",
                    "Any program can record everything this PC plays through this input. Disable it in Sound settings if you do not use it.", "T1123", key + "|loopback"));
            if (device.Kind == AudioDeviceKinds.Network)
                issues.Add(new(Info, AudioIssueCategories.Device, $"Audio is redirected to another computer: {device.Name}",
                    "This endpoint belongs to a remote session; sound is carried over the network.", "T1123", key + "|remote"));
            if (device.Kind == AudioDeviceKinds.Bluetooth && device.IsDefault && (device.Name + device.Adapter).Contains("hands-free", StringComparison.OrdinalIgnoreCase))
                issues.Add(new(Info, AudioIssueCategories.Glitch, $"Bluetooth hands-free mode: {device.Name}",
                    "While an app uses the headset microphone, Bluetooth switches to call mode and sound drops to phone quality. Use the stereo endpoint for music.", "Posture", key + "|hfp"));
            if (device.IsDefault && device.Flow == AudioFlows.Playback && (device.Muted == true || device.VolumePercent == 0))
                issues.Add(new(Info, AudioIssueCategories.Glitch, $"Sound is {(device.Muted == true ? "muted" : "at zero volume")} on {device.Name}",
                    "The default playback device will be silent until it is unmuted.", "Posture", key + "|muted"));
            if (device.IsDefault && device.Flow == AudioFlows.Recording && device.Muted == true)
                issues.Add(new(Info, AudioIssueCategories.Privacy, $"Default microphone is muted: {device.Name}",
                    "Apps that open it receive silence.", "Posture", key + "|mic-muted"));
            if (device.Flow == AudioFlows.Recording && device.IsNew && device.Kind == AudioDeviceKinds.Virtual)
                issues.Add(new(Info, AudioIssueCategories.Device, $"Virtual microphone installed: {device.Name}",
                    "Virtual audio software can feed any sound into apps as if it were your microphone.", "T1123", key + "|virtual"));
        }
    }

    /// <summary>LOW and above become triage findings; INFO stays on the Audio page, and glitches only alert at HIGH.</summary>
    public static IReadOnlyList<SecurityFindingObservation> ToFindings(IReadOnlyList<AudioIssue> issues) =>
        issues
            .Where(issue => SecurityFindingCatalog.Severities.Contains(issue.Severity))
            .Where(issue => issue.Category != AudioIssueCategories.Glitch || Rank(issue.Severity) <= 1)
            .Select(issue => SecurityFindingMapper.Create(SecurityFindingCatalog.Audio, $"Audio {issue.Category}", issue.Severity, issue.Technique,
                issue.Title, issue.Indicator))
            .ToArray();

    public static int Rank(string severity) => severity switch
    {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    };

    [GeneratedRegex(@"\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)\\|\\Temp\\|\\Users\\Public\\|\\ProgramData\\(?!Microsoft\\Windows Defender\\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserWritablePath();
}
