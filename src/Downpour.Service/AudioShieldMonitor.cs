using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.RegularExpressions;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

/// <summary>
/// Audio Shield: reads audio endpoints, which programs are receiving microphone or loopback audio, the audio effect
/// DLLs (APOs) loaded into audiodg.exe, and audio engine health through documented Core Audio, registry, service and
/// event-log APIs. Read-only: no stream is opened, no audio content is read, and nothing is changed.
/// </summary>
public sealed partial class AudioShieldProvider(FileSignatureChecker signatures)
{
    private const string ConsentStore = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone";
    private const string ApoRegistry = @"SOFTWARE\Classes\AudioEngine\AudioProcessingObjects";
    private const string MmDevices = @"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio";
    private static readonly TimeSpan EffectsRefresh = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan EventsRefresh = TimeSpan.FromMinutes(1);
    private readonly Dictionary<int, (string Name, string? Path, bool? Signed, string? Signer, DateTimeOffset Seen)> _processes = [];
    private IReadOnlyList<AudioEffect> _effects = [];
    private DateTimeOffset _effectsAt = DateTimeOffset.MinValue;
    private (int Errors, int Warnings) _events;
    private DateTimeOffset _eventsAt = DateTimeOffset.MinValue;
    private (TimeSpan Cpu, DateTimeOffset At, int Pid)? _engineSample;

    public AudioSnapshot Capture(AudioDeviceBaseline? baseline, out AudioDeviceBaseline updatedBaseline)
    {
        var now = DateTimeOffset.UtcNow;
        var warnings = new List<string>();
        var devices = new List<AudioDevice>();
        var sessions = new List<AudioSession>();
        try
        {
            ReadEndpoints(devices, sessions, warnings);
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or TypeLoadException or UnauthorizedAccessException)
        {
            warnings.Add($"Windows audio could not be read (0x{ex.HResult:X8}); the Windows Audio service may be stopped.");
        }

        var (marked, updated) = AudioThreatAnalyzer.MarkNew(devices, baseline, now);
        updatedBaseline = updated;
        if (now - _effectsAt > EffectsRefresh)
        {
            _effects = ReadEffects(warnings);
            _effectsAt = now;
        }
        var posture = ReadPosture(now, warnings);
        var issues = AudioThreatAnalyzer.Assess(marked, sessions, _effects, posture);
        return new AudioSnapshot(1, now, marked.Take(AudioThreatAnalyzer.MaximumDevices).ToArray(),
            sessions.Take(AudioThreatAnalyzer.MaximumSessions).ToArray(), _effects, posture, issues, warnings.Take(64).ToArray());
    }

    private void ReadEndpoints(List<AudioDevice> devices, List<AudioSession> sessions, List<string> warnings)
    {
        var enumerator = CoreAudio.CreateEnumerator();
        try
        {
            foreach (var flow in new[] { EDataFlow.Render, EDataFlow.Capture })
            {
                var defaultId = DefaultId(enumerator, flow);
                if (enumerator.EnumAudioEndpoints(flow, CoreAudio.DeviceStateAll, out var collection) != 0 || collection is null) continue;
                try
                {
                    collection.GetCount(out var count);
                    for (uint i = 0; i < Math.Min(count, 64u) && devices.Count < AudioThreatAnalyzer.MaximumDevices; i++)
                    {
                        if (collection.Item(i, out var device) != 0 || device is null) continue;
                        try
                        {
                            ReadEndpoint(device, flow, defaultId, devices, sessions);
                        }
                        catch (Exception ex) when (ex is COMException or InvalidCastException)
                        {
                            warnings.Add($"One audio endpoint could not be read (0x{ex.HResult:X8}).");
                        }
                        finally
                        {
                            CoreAudio.Release(device);
                        }
                    }
                }
                finally
                {
                    CoreAudio.Release(collection);
                }
            }
        }
        finally
        {
            CoreAudio.Release(enumerator);
        }
    }

    private static string? DefaultId(IMMDeviceEnumerator enumerator, EDataFlow flow)
    {
        if (enumerator.GetDefaultAudioEndpoint(flow, ERole.Console, out var device) != 0 || device is null) return null;
        try { return device.GetId(out var id) == 0 ? id : null; }
        finally { CoreAudio.Release(device); }
    }

    private void ReadEndpoint(IMMDevice device, EDataFlow flow, string? defaultId, List<AudioDevice> devices, List<AudioSession> sessions)
    {
        if (device.GetId(out var id) != 0 || string.IsNullOrEmpty(id)) return;
        device.GetState(out var state);
        string name = "Audio device", adapter = "", enumeratorName = "";
        int? formFactor = null;
        string? format = null;
        if (device.OpenPropertyStore(0, out var store) == 0 && store is not null)
        {
            try
            {
                name = Clean(CoreAudio.Read(store, CoreAudio.DeviceFriendlyName) as string, 256) ?? name;
                adapter = Clean(CoreAudio.Read(store, CoreAudio.InterfaceFriendlyName) as string, 256) ?? "";
                enumeratorName = Clean(CoreAudio.Read(store, CoreAudio.DeviceEnumeratorName) as string, 64) ?? "";
                if (CoreAudio.Read(store, CoreAudio.EndpointFormFactor) is uint factor) formFactor = (int)factor;
                if (CoreAudio.Read(store, CoreAudio.EngineDeviceFormat) is byte[] blob) format = AudioThreatAnalyzer.DescribeFormat(blob);
            }
            finally
            {
                CoreAudio.Release(store);
            }
        }

        var kind = AudioThreatAnalyzer.ClassifyKind(name, adapter, enumeratorName, formFactor);
        var flowName = flow == EDataFlow.Render ? AudioFlows.Playback : AudioFlows.Recording;
        int? volume = null;
        bool? muted = null;
        double peak = 0;
        if (state == CoreAudio.DeviceStateActive)
        {
            var endpointVolume = CoreAudio.Activate<IAudioEndpointVolume>(device, CoreAudio.AudioEndpointVolumeIid);
            if (endpointVolume is not null)
            {
                try
                {
                    if (endpointVolume.GetMasterVolumeLevelScalar(out var level) == 0) volume = (int)Math.Round(Math.Clamp(level, 0, 1) * 100);
                    if (endpointVolume.GetMute(out var mute) == 0) muted = mute;
                }
                finally { CoreAudio.Release(endpointVolume); }
            }
            // A meter reads the level of streams other programs already run; it never opens the microphone itself.
            var meter = CoreAudio.Activate<IAudioMeterInformation>(device, CoreAudio.AudioMeterInformationIid);
            if (meter is not null)
            {
                try { if (meter.GetPeakValue(out var value) == 0) peak = Math.Clamp(value, 0, 1); }
                finally { CoreAudio.Release(meter); }
            }
            ReadSessions(device, flowName, name, kind, sessions);
        }

        devices.Add(new AudioDevice(id.Length <= 512 ? id : id[..512], name, adapter, flowName, StateName(state), kind,
            id == defaultId, format, volume, muted, peak, false, null));
    }

    private void ReadSessions(IMMDevice device, string flow, string deviceName, string deviceKind, List<AudioSession> sessions)
    {
        var manager = CoreAudio.Activate<IAudioSessionManager2>(device, CoreAudio.AudioSessionManager2Iid);
        if (manager is null) return;
        try
        {
            if (manager.GetSessionEnumerator(out var list) != 0 || list is null) return;
            try
            {
                list.GetCount(out var count);
                for (var i = 0; i < Math.Min(count, 128) && sessions.Count < AudioThreatAnalyzer.MaximumSessions; i++)
                {
                    if (list.GetSession(i, out var control) != 0 || control is null) continue;
                    try
                    {
                        if (control.IsSystemSoundsSession() == 0) continue;
                        control.GetState(out var sessionState);
                        // Playback is listed only while playing; recording sessions are listed while open, idle or not.
                        if (sessionState == 2 || (flow == AudioFlows.Playback && sessionState != 1)) continue;
                        if (control.GetProcessId(out var pid) != 0) continue;
                        double peak = 0;
                        if (control is IAudioMeterInformation meter && meter.GetPeakValue(out var value) == 0) peak = Math.Clamp(value, 0, 1);
                        var process = DescribeProcess((int)pid);
                        sessions.Add(new AudioSession(flow, deviceName, deviceKind, (int)pid, process.Name, process.Path,
                            sessionState == 1 ? "active" : "idle", peak, HasWindow((int)pid), process.Signed, process.Signer));
                    }
                    catch (Exception ex) when (ex is COMException or InvalidCastException) { }
                    finally { CoreAudio.Release(control); }
                }
            }
            finally { CoreAudio.Release(list); }
        }
        finally { CoreAudio.Release(manager); }
    }

    private (string Name, string? Path, bool? Signed, string? Signer) DescribeProcess(int pid)
    {
        var now = DateTimeOffset.UtcNow;
        if (_processes.TryGetValue(pid, out var known) && now - known.Seen < TimeSpan.FromMinutes(2))
            return (known.Name, known.Path, known.Signed, known.Signer);
        var name = pid == 0 ? "System" : "Unknown";
        string? path = null;
        try
        {
            using var process = Process.GetProcessById(pid);
            name = Clean(process.ProcessName, 128) ?? name;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { }
        if (pid > 4) path = ImagePath(pid);
        var signature = path is null ? null : signatures.Check(path);
        if (_processes.Count > 512) _processes.Clear();
        _processes[pid] = (name, path, signature?.Signed, signature?.Signer is { } s ? Clean(s, 512) : null, now);
        return (name, path, signature?.Signed, signature?.Signer is { } signer ? Clean(signer, 512) : null);
    }

    private static bool HasWindow(int pid)
    {
        if (pid <= 4) return false;
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.MainWindowHandle != IntPtr.Zero;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private IReadOnlyList<AudioEffect> ReadEffects(List<string> warnings)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var registered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var apos = Registry.LocalMachine.OpenSubKey(ApoRegistry);
            foreach (var clsid in apos?.GetSubKeyNames().Take(MaximumEffectKeys) ?? [])
            {
                if (!Guid.TryParse(clsid, out _)) continue;
                using var key = apos!.OpenSubKey(clsid);
                registered.Add(clsid);
                names[clsid] = Clean(key?.GetValue("FriendlyName") as string, 256) ?? clsid;
            }
            // Endpoint effect slots (FxProperties) can name APOs that are not in the list above.
            foreach (var flow in new[] { "Render", "Capture" })
            {
                using var root = Registry.LocalMachine.OpenSubKey($@"{MmDevices}\{flow}");
                foreach (var endpoint in root?.GetSubKeyNames().Take(128) ?? [])
                {
                    using var fx = root!.OpenSubKey($@"{endpoint}\FxProperties");
                    foreach (var valueName in fx?.GetValueNames().Take(128) ?? [])
                    {
                        var value = fx!.GetValue(valueName);
                        var strings = value switch { string single => [single], string[] many => many, _ => Array.Empty<string>() };
                        foreach (var candidate in strings.Take(16))
                            if (Guid.TryParse(candidate, out var guid)) names.TryAdd(guid.ToString("B").ToUpperInvariant(), "");
                    }
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            warnings.Add("Audio effect registrations could not be read.");
        }

        var effects = new List<AudioEffect>();
        foreach (var (clsid, apoName) in names.Take(AudioThreatAnalyzer.MaximumEffects * 2))
        {
            var (dll, description) = ComServer(clsid);
            // FxProperties also holds processing-mode GUIDs; only real COM servers or registered APOs are effects.
            if (dll is null && !registered.Contains(clsid)) continue;
            var label = apoName.Length > 0 ? apoName : description ?? clsid;
            var path = ResolveDll(dll);
            var signature = path is null ? null : signatures.Check(path);
            effects.Add(new AudioEffect(clsid, label, path ?? (dll is null ? null : Clean(dll, 1024)), path is null && dll is not null ? false : signature?.Signed,
                signature?.Signer is { } signer ? Clean(signer, 512) : null, signature?.Microsoft == true));
            if (effects.Count >= AudioThreatAnalyzer.MaximumEffects) break;
        }
        return effects.OrderBy(e => e.Microsoft).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private const int MaximumEffectKeys = 512;

    private static (string? Dll, string? Description) ComServer(string clsid)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}");
            if (key is null) return (null, null);
            using var server = key.OpenSubKey("InprocServer32");
            return (server?.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string, Clean(key.GetValue(null) as string, 256));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return (null, null);
        }
    }

    /// <summary>A COM server path as a fully qualified local file, or null when it is missing, remote or malformed.</summary>
    internal static string? ResolveDll(string? dll)
    {
        if (string.IsNullOrWhiteSpace(dll) || dll.Length > 1024) return null;
        try
        {
            var expanded = Environment.ExpandEnvironmentVariables(dll.Trim().Trim('"'));
            if (expanded.StartsWith(@"\\", StringComparison.Ordinal) || expanded.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return null;
            if (!Path.IsPathFullyQualified(expanded))
            {
                if (expanded.Contains('\\') || expanded.Contains('/')) return null;
                expanded = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), expanded);
            }
            var full = Path.GetFullPath(expanded);
            return File.Exists(full) ? full : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private AudioPosture ReadPosture(DateTimeOffset now, List<string> warnings)
    {
        bool? micAllowed = null, desktopAllowed = null;
        try
        {
            using var consent = Registry.CurrentUser.OpenSubKey(ConsentStore);
            micAllowed = Allow(consent?.GetValue("Value") as string);
            using var desktop = consent?.OpenSubKey("NonPackaged");
            desktopAllowed = Allow(desktop?.GetValue("Value") as string);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException) { }

        var engines = Process.GetProcessesByName("audiodg");
        string? enginePath = null;
        double cpu = 0;
        try
        {
            if (engines.FirstOrDefault() is { } engine)
            {
                enginePath = ImagePath(engine.Id);
                try
                {
                    var total = engine.TotalProcessorTime;
                    if (_engineSample is { } last && last.Pid == engine.Id && now > last.At)
                        cpu = Math.Clamp((total - last.Cpu).TotalMilliseconds / ((now - last.At).TotalMilliseconds * Environment.ProcessorCount) * 100, 0, 100);
                    _engineSample = (total, now, engine.Id);
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
        finally
        {
            foreach (var engine in engines) engine.Dispose();
        }
        bool? engineSigned = enginePath is null ? null : signatures.Check(enginePath) switch
        {
            { Signed: true, Microsoft: true } => true,
            { Signed: false } or { Signed: true, Microsoft: false } => false,
            _ => null,
        };

        if (now - _eventsAt > EventsRefresh)
        {
            _events = (CountAudioEvents(2), CountAudioEvents(3));
            _eventsAt = now;
        }
        return new AudioPosture(micAllowed, desktopAllowed, ServiceState("Audiosrv"), ServiceState("AudioEndpointBuilder"),
            Math.Round(cpu, 1), enginePath, engineSigned, engines.Length, _events.Errors, _events.Warnings);
    }

    private static bool? Allow(string? value) => value switch
    {
        "Allow" => true,
        "Deny" => false,
        _ => null,
    };

    private static string ServiceState(string name)
    {
        try
        {
            using var service = new ServiceController(name);
            return service.Status.ToString();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or ArgumentException)
        {
            return "Unknown";
        }
    }

    /// <summary>Counts (does not read) Microsoft-Windows-Audio/Operational events of one level from the last 24 hours.</summary>
    private static int CountAudioEvents(int level)
    {
        try
        {
            var query = new EventLogQuery("Microsoft-Windows-Audio/Operational", PathType.LogName,
                $"*[System[Level={level} and TimeCreated[timediff(@SystemTime) <= 86400000]]]") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            var count = 0;
            while (count < 500 && reader.ReadEvent() is { } record)
            {
                record.Dispose();
                count++;
            }
            return count;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            return 0;
        }
    }

    private static string StateName(uint state) => state switch
    {
        CoreAudio.DeviceStateActive => "active",
        CoreAudio.DeviceStateDisabled => "disabled",
        CoreAudio.DeviceStateNotPresent => "not present",
        CoreAudio.DeviceStateUnplugged => "unplugged",
        _ => "unknown",
    };

    private static string? Clean(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var clean = new string(value.Where(ch => !char.IsControl(ch)).Take(max).ToArray()).Trim();
        return clean.Length == 0 ? null : clean;
    }

    private static string? ImagePath(int pid)
    {
        using var handle = OpenProcess(0x1000, false, (uint)pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (handle.IsInvalid) return null;
        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        if (!QueryFullProcessImageNameW(handle, 0, buffer, ref size) || size == 0) return null;
        var path = new string(buffer, 0, (int)size);
        return Path.IsPathFullyQualified(path) ? path : null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);
}

/// <summary>
/// Samples Audio Shield every second, keeps the endpoint first-seen baseline (hashes only) in
/// state\audio-devices.v1.json, raises triage findings, and serves the latest snapshot on Downpour.Audio.v1
/// (length-prefixed JSON, current-user ACL, read-only).
/// </summary>
public sealed class AudioShieldMonitor(AudioShieldProvider provider, SecurityAlertRepository alerts, ILogger<AudioShieldMonitor> logger,
    string? baselinePath = null, string pipeName = AudioClient.PipeName) : BackgroundService
{
    public static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(1);
    private const long MaximumBaselineBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();
    private AudioSnapshot? _latest;
    private AudioDeviceBaseline? _baseline;
    private string _findingKey = "";
    private DateTimeOffset _findingsAt = DateTimeOffset.MinValue;

    private string BaselinePath => baselinePath ?? DefaultBaselinePath();

    private static string DefaultBaselinePath()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var file = Path.Combine(root, "audio-devices.v1.json");
        SecureJournalDirectory.RestrictExistingFile(file);
        return file;
    }

    public AudioSnapshot? Latest
    {
        get { lock (_gate) return _latest; }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _baseline = LoadBaseline();
        _ = Task.Run(() => ServePipeAsync(stoppingToken), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await SampleOnceAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Audio Shield sample failed.");
            }
            try { await Task.Delay(SampleInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal async Task SampleOnceAsync(CancellationToken token)
    {
        var before = _baseline;
        AudioDeviceBaseline? after = null;
        var snapshot = await Task.Run(() => provider.Capture(before, out after), token);
        lock (_gate) _latest = snapshot;
        if (after is not null && (before is null || after.Devices.Count != before.Devices.Count))
        {
            _baseline = after;
            SaveBaseline(after);
        }

        var findings = AudioThreatAnalyzer.ToFindings(snapshot.Issues);
        var key = string.Join('\n', findings.Select(f => $"{f.Severity}|{f.Indicator}"));
        if (findings.Count > 0 && (key != _findingKey || DateTimeOffset.UtcNow - _findingsAt > TimeSpan.FromMinutes(5)))
        {
            await alerts.IngestFindingsAsync(findings.Take(SecurityAlertRepository.MaximumFindingsPerIngest).ToArray(), DateTimeOffset.UtcNow, token);
            _findingsAt = DateTimeOffset.UtcNow;
        }
        _findingKey = key;
    }

    private AudioDeviceBaseline? LoadBaseline()
    {
        try
        {
            if (!File.Exists(BaselinePath) || new FileInfo(BaselinePath).Length > MaximumBaselineBytes) return null;
            var baseline = JsonSerializer.Deserialize<AudioDeviceBaseline>(File.ReadAllText(BaselinePath), Json);
            return baseline is { SchemaVersion: 1, Devices.Count: <= 4096 } ? baseline : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            logger.LogWarning(ex, "The audio device baseline could not be read; starting a new one.");
            return null;
        }
    }

    private void SaveBaseline(AudioDeviceBaseline baseline)
    {
        try
        {
            var temp = BaselinePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(baseline, Json));
            File.Move(temp, BaselinePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "The audio device baseline could not be written.");
        }
    }

    private async Task ServePipeAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough, 0, 4096, PipeSecurityFactory.CreateCurrentUserReadSecurity());
                await pipe.WaitForConnectionAsync(stoppingToken);
                var snapshot = Latest ?? new AudioSnapshot(1, DateTimeOffset.UtcNow, [], [], [],
                    new AudioPosture(null, null, "Unknown", "Unknown", 0, null, null, 0, 0, 0), [], ["The first audio sample is still being collected."]);
                var payload = BoundedJson.Serialize(snapshot);
                var length = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(length, payload.Length);
                await pipe.WriteAsync(length, stoppingToken);
                await pipe.WriteAsync(payload, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or InvalidOperationException)
            {
                logger.LogDebug(ex, "An audio client disconnected or the reply could not be written.");
            }
        }
    }
}
