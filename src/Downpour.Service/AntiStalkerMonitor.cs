using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

/// <summary>
/// Reads who or what can watch this PC right now (DN-030): Windows' per-app usage records for camera, microphone,
/// screen capture and location; Remote Desktop sessions; remote-control programs; and installed or running monitoring
/// software. Read-only and local: nothing is sent anywhere, no screen or audio content is touched.
/// </summary>
public sealed class AntiStalkerProvider(InstalledSoftwareInventoryProvider installed)
{
    private const int MaximumAppsPerCapability = 200;
    private const string ConsentStore = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
    private IReadOnlyList<MonitoringSoftware> _installedMonitoring = [];
    private DateTimeOffset _installedCheckedAt = DateTimeOffset.MinValue;

    public AntiStalkerSnapshot Capture(IReadOnlyList<WatchEvent> log)
    {
        var warnings = new List<string>();
        var sensors = ReadSensorUsage(warnings);
        var sessions = ReadRemoteSessions(warnings);
        var running = new List<RemoteControlProcess>();
        var monitoring = new List<MonitoringSoftware>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (AntiStalkerAnalyzer.MatchRemoteControl(process.Id, process.ProcessName) is { } tool) running.Add(tool);
                if (AntiStalkerAnalyzer.MatchMonitoring(process.ProcessName, "running process") is { } software) monitoring.Add(software);
            }
        }
        // The installed-program list changes rarely and is comparatively expensive to read.
        if (DateTimeOffset.UtcNow - _installedCheckedAt > TimeSpan.FromMinutes(5))
        {
            _installedMonitoring = installed.Capture().Software
                .Select(entry => AntiStalkerAnalyzer.MatchMonitoring(entry.Name, "installed program"))
                .OfType<MonitoringSoftware>()
                .ToArray();
            _installedCheckedAt = DateTimeOffset.UtcNow;
        }
        monitoring.AddRange(_installedMonitoring);
        return new AntiStalkerSnapshot(1, DateTimeOffset.UtcNow, sensors, sessions, running,
            monitoring.DistinctBy(m => (m.Product, m.Source)).Take(64).ToArray(), log, warnings);
    }

    private static List<SensorUsage> ReadSensorUsage(List<string> warnings)
    {
        var results = new List<SensorUsage>();
        try
        {
            using var store = Registry.CurrentUser.OpenSubKey(ConsentStore);
            if (store is null)
            {
                warnings.Add("Windows privacy usage records are not available on this edition of Windows.");
                return results;
            }
            foreach (var capability in WatchCapabilities.All)
            {
                using var capabilityKey = store.OpenSubKey(capability);
                if (capabilityKey is null) continue;
                var count = 0;
                foreach (var (app, key) in Apps(capabilityKey))
                {
                    using (key)
                    {
                        if (++count > MaximumAppsPerCapability) break;
                        var start = FileTime(key.GetValue("LastUsedTimeStart"));
                        if (start is null) continue;
                        var stopRaw = key.GetValue("LastUsedTimeStop");
                        var stop = FileTime(stopRaw);
                        var inUse = stopRaw is long and 0;
                        results.Add(new SensorUsage(capability, Bound(app, 260), Bound(AntiStalkerAnalyzer.DisplayName(app), 128), start, stop, inUse));
                    }
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            warnings.Add($"Windows privacy usage records could not be read ({ex.GetType().Name}).");
        }
        return results;
    }

    private static IEnumerable<(string App, RegistryKey Key)> Apps(RegistryKey capabilityKey)
    {
        foreach (var name in capabilityKey.GetSubKeyNames())
        {
            if (name.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
            {
                using var desktopApps = capabilityKey.OpenSubKey(name);
                if (desktopApps is null) continue;
                foreach (var app in desktopApps.GetSubKeyNames())
                    if (desktopApps.OpenSubKey(app) is { } key) yield return (app, key);
            }
            else if (capabilityKey.OpenSubKey(name) is { } key)
            {
                yield return (name, key);
            }
        }
    }

    private static DateTimeOffset? FileTime(object? value) =>
        value is long ticks && ticks > 0 && ticks < DateTime.MaxValue.ToFileTimeUtc() ? DateTimeOffset.FromFileTime(ticks).ToUniversalTime() : null;

    private static string Bound(string value, int max) => value.Length <= max ? value : value[..max];

    /// <summary>Sessions connected from another computer (WTS protocol RDP or other non-console protocols).</summary>
    internal static List<RemoteSessionInfo> ReadRemoteSessions(List<string> warnings)
    {
        var sessions = new List<RemoteSessionInfo>();
        var current = Process.GetCurrentProcess().SessionId;
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            warnings.Add("Windows session list could not be read.");
            return sessions;
        }
        try
        {
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var i = 0; i < count && i < 64; i++)
            {
                var info = Marshal.PtrToStructure<WtsSessionInfo>(buffer + i * size);
                var protocol = QueryShort(info.SessionId, WtsClientProtocolType);
                if (protocol is null or 0) continue; // 0 = this computer's console
                var state = info.State switch { 0 => "Active", 1 => "Connected", 4 => "Disconnected", _ => "Other" };
                sessions.Add(new RemoteSessionInfo(info.SessionId, state, protocol == 2 ? "Remote Desktop (RDP)" : "remote",
                    QueryString(info.SessionId, WtsClientName), QueryAddress(info.SessionId), info.SessionId == current));
            }
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
        return sessions;
    }

    private static ushort? QueryShort(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, infoClass, out var buffer, out var bytes)) return null;
        try { return bytes >= 2 ? (ushort)Marshal.ReadInt16(buffer) : null; }
        finally { WTSFreeMemory(buffer); }
    }

    private static string? QueryString(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, infoClass, out var buffer, out _)) return null;
        try
        {
            var value = Marshal.PtrToStringUni(buffer);
            return string.IsNullOrWhiteSpace(value) ? null : Bound(value, 64);
        }
        finally { WTSFreeMemory(buffer); }
    }

    private static string? QueryAddress(int sessionId)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WtsClientAddress, out var buffer, out var bytes)) return null;
        try
        {
            // WTS_CLIENT_ADDRESS { DWORD AddressFamily; BYTE Address[20]; } — IPv4 bytes sit at offset 2 of Address.
            if (bytes < 24 || Marshal.ReadInt32(buffer) != 2) return null;
            var raw = new byte[4];
            Marshal.Copy(buffer + 4 + 2, raw, 0, 4);
            return new IPAddress(raw).ToString();
        }
        finally { WTSFreeMemory(buffer); }
    }

    private const int WtsClientName = 10, WtsClientAddress = 14, WtsClientProtocolType = 16;

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}

/// <summary>
/// Samples every 10 seconds, writes every start/stop transition to a local watch log
/// (state\watch-log.v1.jsonl, bounded with one rollover), raises triage findings, and serves the latest snapshot on
/// Downpour.AntiStalker.v1 (length-prefixed JSON, current-user ACL, read-only).
/// </summary>
public sealed class AntiStalkerMonitor(AntiStalkerProvider provider, SecurityAlertRepository alerts, ILogger<AntiStalkerMonitor> logger,
    string? logPath = null, string pipeName = AntiStalkerClient.PipeName) : BackgroundService
{
    public static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(10);
    private const int MaximumLogEntries = 500;
    private const long MaximumLogBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions LogJson = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();
    private readonly List<WatchEvent> _log = [];
    private AntiStalkerSnapshot? _latest;
    private DateTimeOffset _findingsAt = DateTimeOffset.MinValue;

    private string LogPath => logPath ?? DefaultLogPath();

    private static string DefaultLogPath()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var file = Path.Combine(root, "watch-log.v1.jsonl");
        SecureJournalDirectory.RestrictExistingFile(file);
        return file;
    }

    public AntiStalkerSnapshot? Latest
    {
        get { lock (_gate) return _latest; }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LoadLog();
        _ = Task.Run(() => ServePipeAsync(stoppingToken), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await SampleOnceAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Anti-stalker sample failed.");
            }
            try { await Task.Delay(SampleInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal async Task SampleOnceAsync(CancellationToken token)
    {
        AntiStalkerSnapshot? previous;
        IReadOnlyList<WatchEvent> logCopy;
        lock (_gate)
        {
            previous = _latest;
            logCopy = _log.ToArray();
        }
        var current = await Task.Run(() => provider.Capture(logCopy), token);
        var events = AntiStalkerAnalyzer.Diff(previous, current);
        lock (_gate)
        {
            foreach (var e in events) _log.Add(e);
            if (_log.Count > MaximumLogEntries) _log.RemoveRange(0, _log.Count - MaximumLogEntries);
            _latest = current with { Log = _log.AsEnumerable().Reverse().Take(200).ToArray() };
        }
        AppendToFile(events);
        foreach (var e in events.Where(e => e.Severity is "HIGH" or "CRITICAL"))
            logger.LogWarning("Watch log: {Subject}: {Detail}", e.Subject, e.Detail);

        if (DateTimeOffset.UtcNow - _findingsAt > TimeSpan.FromMinutes(1) || events.Count > 0)
        {
            var findings = AntiStalkerAnalyzer.Findings(current);
            if (findings.Count > 0) await alerts.IngestFindingsAsync(findings.Take(SecurityAlertRepository.MaximumFindingsPerIngest).ToArray(), DateTimeOffset.UtcNow, token);
            _findingsAt = DateTimeOffset.UtcNow;
        }
    }

    private void LoadLog()
    {
        try
        {
            if (!File.Exists(LogPath) || new FileInfo(LogPath).Length > MaximumLogBytes * 2) return;
            foreach (var line in File.ReadLines(LogPath).TakeLast(MaximumLogEntries))
            {
                try
                {
                    if (JsonSerializer.Deserialize<WatchEvent>(line, LogJson) is { Subject.Length: <= 256, Detail.Length: <= 512 } entry) _log.Add(entry);
                }
                catch (JsonException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "The watch log could not be read.");
        }
    }

    private void AppendToFile(IReadOnlyList<WatchEvent> events)
    {
        if (events.Count == 0) return;
        try
        {
            if (File.Exists(LogPath) && new FileInfo(LogPath).Length > MaximumLogBytes) File.Move(LogPath, LogPath + ".1", overwrite: true);
            File.AppendAllLines(LogPath, events.Select(e => JsonSerializer.Serialize(e, LogJson)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "The watch log could not be written.");
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
                var snapshot = Latest ?? new AntiStalkerSnapshot(1, DateTimeOffset.UtcNow, [], [], [], [], [], ["The first sample is still being collected."]);
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
                logger.LogDebug(ex, "An anti-stalker client disconnected or the reply could not be written.");
            }
        }
    }
}
