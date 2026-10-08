using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class AudioShieldTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);

    private static readonly AudioPosture Healthy = new(true, true, "Running", "Running", 0.4, @"C:\Windows\System32\audiodg.exe", true, 1, 0, 0);

    private static AudioDevice Device(string id, string name, string flow = AudioFlows.Playback, string kind = AudioDeviceKinds.BuiltIn,
        bool isDefault = false, bool? muted = false, int? volume = 50, bool isNew = false, string adapter = "Realtek(R) Audio") =>
        new(id, name, adapter, flow, "active", kind, isDefault, "48 kHz, 24-bit, 2 ch", volume, muted, 0, isNew, isNew ? T0 : null);

    private static AudioSession Listener(string name, string? path, bool? signed = true, bool window = true, string kind = AudioDeviceKinds.BuiltIn, string state = "active") =>
        new(AudioFlows.Recording, "Microphone (Realtek(R) Audio)", kind, 4242, name, path, state, 0.2, window, signed, signed == true ? "CN=Vendor" : null);

    private static IReadOnlyList<AudioIssue> Assess(IReadOnlyList<AudioSession>? sessions = null, IReadOnlyList<AudioEffect>? effects = null,
        AudioPosture? posture = null, IReadOnlyList<AudioDevice>? devices = null) =>
        AudioThreatAnalyzer.Assess(devices ?? [Device("{0.0.0}.{a}", "Speakers", isDefault: true)], sessions ?? [], effects ?? [], posture ?? Healthy);

    [Fact]
    public void HealthyQuietSystemHasOnlyPrivacyNotes()
    {
        var issues = Assess();
        Assert.All(issues, issue => Assert.Equal(AudioThreatAnalyzer.Info, issue.Severity));
        Assert.Empty(AudioThreatAnalyzer.ToFindings(issues));
    }

    [Theory]
    [InlineData("Teams", @"C:\Users\a\AppData\Local\Microsoft\Teams\current\Teams.exe", true, true, "INFO")]
    [InlineData("chrome", @"C:\Program Files\Google\Chrome\Application\chrome.exe", true, true, "INFO")]
    [InlineData("updater", @"C:\Users\a\AppData\Roaming\x\updater.exe", false, false, "HIGH")]
    [InlineData("helper", @"C:\Users\a\AppData\Roaming\x\helper.exe", true, true, "MEDIUM")]
    [InlineData("svcagent", @"C:\Program Files\Vendor\svcagent.exe", true, false, "MEDIUM")]
    [InlineData("recorder", @"C:\Program Files\Vendor\recorder.exe", true, true, "INFO")]
    public void ListenerSeverityDependsOnSignatureLocationAndVisibility(string name, string path, bool signed, bool window, string severity)
    {
        var issue = Assert.Single(Assess([Listener(name, path, signed, window)]), i => i.Category == AudioIssueCategories.Listening);
        Assert.Equal(severity, issue.Severity);
        Assert.Equal("T1123", issue.Technique);
    }

    [Fact]
    public void IdleRecordingSessionsAreNotReportedAsListening()
    {
        Assert.DoesNotContain(Assess([Listener("updater", @"C:\Temp\u.exe", false, state: "idle")]), i => i.Category == AudioIssueCategories.Listening);
    }

    [Fact]
    public void KnownMonitoringSoftwareListeningIsHigh()
    {
        var issue = Assert.Single(Assess([Listener("mspy", @"C:\Program Files\x\mspy.exe")]), i => i.Category == AudioIssueCategories.Listening);
        Assert.Equal("HIGH", issue.Severity);
        Assert.StartsWith("Monitoring software", issue.Title);
    }

    [Fact]
    public void UnknownProgramRecordingLoopbackIsFlagged()
    {
        var issue = Assert.Single(Assess([Listener("capture", @"C:\Program Files\x\capture.exe", kind: AudioDeviceKinds.Loopback)]),
            i => i.Category == AudioIssueCategories.Listening);
        Assert.Equal("MEDIUM", issue.Severity);
        Assert.Contains("everything you hear", issue.Title);
    }

    [Fact]
    public void AudioEffectsAreJudgedBySignatureAndFolder()
    {
        AudioEffect[] effects =
        [
            new("{1}", "Realtek APO", @"C:\Windows\System32\RltkAPO64.dll", true, "Realtek Semiconductor Corp.", false),
            new("{2}", "Rogue APO", @"C:\Windows\System32\rogue.dll", false, null, false),
            new("{3}", "User APO", @"C:\Users\a\AppData\Local\fx.dll", true, "CN=Someone", false),
            new("{4}", "Broken APO", null, null, null, false),
        ];
        var issues = Assess(effects: effects);
        Assert.DoesNotContain(issues, i => i.Title.Contains("Realtek"));
        Assert.Contains(issues, i => i.Severity == "HIGH" && i.Title.Contains("Rogue APO") && i.Technique == "T1546.015");
        Assert.Contains(issues, i => i.Severity == "HIGH" && i.Title.Contains("User APO"));
        Assert.Contains(issues, i => i.Severity == AudioThreatAnalyzer.Info && i.Category == AudioIssueCategories.Glitch && i.Title.Contains("Broken APO"));
    }

    [Fact]
    public void MasqueradingAudioEngineIsCritical()
    {
        var issues = Assess(posture: Healthy with { AudioEnginePath = @"C:\Users\Public\audiodg.exe", AudioEngineSigned = false });
        Assert.Equal(2, issues.Count(i => i.Severity == "CRITICAL" && i.Technique == "T1036.005"));
        Assert.Equal("CRITICAL", issues[0].Severity);
    }

    [Fact]
    public void GlitchCausesAreExplainedAndOnlyServiceOutagesAlert()
    {
        var issues = Assess(
            posture: Healthy with { AudioService = "Stopped", AudioEngineCpuPercent = 32, AudioErrors24h = 4 },
            devices: [Device("{0.0.0}.{a}", "Speakers", isDefault: true, muted: true),
                Device("{0.0.0}.{b}", "Headset (WH-1000XM4 Hands-Free)", kind: AudioDeviceKinds.Bluetooth, isDefault: true, adapter: "WH-1000XM4 Hands-Free")]);
        Assert.Contains(issues, i => i.Severity == "HIGH" && i.Title.StartsWith("Windows Audio service is stopped", StringComparison.Ordinal));
        Assert.Contains(issues, i => i.Severity == "MEDIUM" && i.Title.Contains("32% CPU"));
        Assert.Contains(issues, i => i.Title.StartsWith("Sound is muted", StringComparison.Ordinal));
        Assert.Contains(issues, i => i.Title.StartsWith("Bluetooth hands-free", StringComparison.Ordinal));
        Assert.Contains(issues, i => i.Title.Contains("4 audio errors"));
        var finding = Assert.Single(AudioThreatAnalyzer.ToFindings(issues));
        Assert.Equal(SecurityFindingCatalog.Audio, finding.Source);
        Assert.Equal("T1489", finding.Technique);
    }

    [Fact]
    public void NoActivePlaybackDeviceIsAGlitch()
    {
        var issues = Assess(devices: [Device("{0.0.1}.{m}", "Microphone", AudioFlows.Recording)]);
        Assert.Contains(issues, i => i.Indicator == "no-playback" && i.Severity == "MEDIUM");
    }

    [Fact]
    public void NewMicrophoneAndLoopbackDevicesAreReported()
    {
        var issues = Assess(devices:
        [
            Device("{0.0.0}.{a}", "Speakers", isDefault: true),
            Device("{0.0.1}.{n}", "Headset Microphone (AirPods)", AudioFlows.Recording, AudioDeviceKinds.Bluetooth, isNew: true),
            Device("{0.0.1}.{s}", "Stereo Mix (Realtek(R) Audio)", AudioFlows.Recording, AudioDeviceKinds.Loopback),
        ]);
        Assert.Contains(issues, i => i.Severity == "MEDIUM" && i.Title.StartsWith("New microphone appeared", StringComparison.Ordinal));
        Assert.Contains(issues, i => i.Severity == "LOW" && i.Title.StartsWith("Loopback recording", StringComparison.Ordinal));
        Assert.Equal(2, AudioThreatAnalyzer.ToFindings(issues).Count);
    }

    [Fact]
    public void BaselineIsTrustOnFirstUseAndStoresHashesOnly()
    {
        var first = new[] { Device("{0.0.1.00000000}.{secret-endpoint}", "Mic", AudioFlows.Recording) };
        var (marked, baseline) = AudioThreatAnalyzer.MarkNew(first, null, T0);
        Assert.False(marked[0].IsNew);
        Assert.DoesNotContain("secret-endpoint", JsonSerializer.Serialize(baseline));

        var later = first.Append(Device("{0.0.1.00000000}.{new}", "USB Mic", AudioFlows.Recording, AudioDeviceKinds.Usb)).ToArray();
        var (again, updated) = AudioThreatAnalyzer.MarkNew(later, baseline, T0.AddDays(1));
        Assert.False(again[0].IsNew);
        Assert.True(again[1].IsNew);
        var (aged, _) = AudioThreatAnalyzer.MarkNew(later, updated, T0.AddDays(9));
        Assert.All(aged, d => Assert.False(d.IsNew));
    }

    [Theory]
    [InlineData("Stereo Mix", "Realtek(R) Audio", "HDAUDIO", 10, AudioDeviceKinds.Loopback)]
    [InlineData("Headphones", "WH-1000XM4", "BTHENUM", 3, AudioDeviceKinds.Bluetooth)]
    [InlineData("CABLE Output", "VB-Audio Virtual Cable", "ROOT", 4, AudioDeviceKinds.Virtual)]
    [InlineData("LG TV", "NVIDIA High Definition Audio", "HDAUDIO", 9, AudioDeviceKinds.Hdmi)]
    [InlineData("Microphone", "Yeti Stereo Microphone", "USB", 4, AudioDeviceKinds.Usb)]
    [InlineData("Speakers", "Realtek(R) Audio", "HDAUDIO", 1, AudioDeviceKinds.BuiltIn)]
    [InlineData("Remote Audio", "", "", 0, AudioDeviceKinds.Network)]
    public void DevicesAreClassified(string name, string adapter, string bus, int formFactor, string kind) =>
        Assert.Equal(kind, AudioThreatAnalyzer.ClassifyKind(name, adapter, bus, formFactor));

    [Fact]
    public void WaveFormatsAreDescribed()
    {
        byte[] pcm = [1, 0, 2, 0, 0x80, 0xBB, 0, 0, 0, 0x77, 1, 0, 4, 0, 16, 0];
        Assert.Equal("48 kHz, 16-bit, 2 ch", AudioThreatAnalyzer.DescribeFormat(pcm));
        byte[] extensible = [0xFE, 0xFF, 2, 0, 0x44, 0xAC, 0, 0, 0, 0, 0, 0, 8, 0, 32, 0, 22, 0, 24, 0, 3, 0, 0, 0];
        Assert.Equal("44.1 kHz, 24-bit, 2 ch", AudioThreatAnalyzer.DescribeFormat(extensible));
        Assert.Null(AudioThreatAnalyzer.DescribeFormat([1, 2, 3]));
    }

    [Fact]
    public void ClientRejectsMalformedSnapshots()
    {
        var good = new AudioSnapshot(1, T0, [Device("id", "Speakers")], [Listener("Teams", null)], [], Healthy, Assess(), []);
        Assert.True(AudioClient.IsValid(good));
        Assert.False(AudioClient.IsValid(good with { SchemaVersion = 2 }));
        Assert.False(AudioClient.IsValid(good with { Devices = [Device("id", "bad\u0007name")] }));
        Assert.False(AudioClient.IsValid(good with { Sessions = [Listener("Teams", null) with { Peak = 4 }] }));
        Assert.False(AudioClient.IsValid(good with { Issues = [new("URGENT", "Listening", "t", "d", "T1123", "x")] }));
        Assert.False(AudioClient.IsValid(good with { Posture = Healthy with { AudioEngineCpuPercent = 400 } }));
    }

    [Theory]
    [InlineData(@"\\server\share\apo.dll")]
    [InlineData(@"sub\apo.dll")]
    [InlineData(@"C:\definitely\missing\apo.dll")]
    [InlineData("")]
    public void EffectDllPathsMustBeLocalAndPresent(string dll) => Assert.Null(AudioShieldProvider.ResolveDll(dll));

    [Fact]
    public void BareEffectDllNamesResolveToSystem32() =>
        Assert.EndsWith(@"\System32\kernel32.dll", AudioShieldProvider.ResolveDll("kernel32.dll"), StringComparison.OrdinalIgnoreCase);
}
