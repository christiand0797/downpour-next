using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

/// <summary>
/// Keeps the allow-listed public threat databases current and checks this PC against them: live TCP connections (with the
/// owning program), names in the DNS cache, loaded kernel drivers, and running programs outside the Windows folder.
/// Feeds are downloaded whole, so nothing about this PC is sent to any source. Matches become triage findings; nothing is
/// blocked or changed. Serves <see cref="ThreatDatabaseClient.PipeName"/> (snapshot, refresh, local lookup).
/// </summary>
public sealed class ThreatDatabaseService(
    SecurityAlertRepository alerts,
    SensorSettingsStore settings,
    DnsInventoryProvider dns,
    DriverInventoryProvider drivers,
    ILogger<ThreatDatabaseService> logger,
    ThreatFeedCache? cache = null,
    ThreatFeedDownloader? downloader = null,
    string pipeName = ThreatDatabaseClient.PipeName,
    IAuthenticodeVerifier? signatures = null) : BackgroundService
{
    public static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan ManualRefreshCooldown = TimeSpan.FromMinutes(2);
    private const int MaximumMatches = 300;
    private const int MaximumConnections = 400;
    private const long MaximumHashedFileBytes = 128L * 1024 * 1024;
    private const int MaximumProgramsPerSweep = 600;

    private readonly ThreatFeedCache _cache = cache ?? ThreatFeedCache.CreateForCurrentUser();
    private readonly ThreatFeedDownloader _downloader = downloader ?? new ThreatFeedDownloader();
    private readonly object _gate = new();
    private readonly Dictionary<string, FeedState> _feeds = ThreatFeedCatalog.All.ToDictionary(f => f.Id, f => new FeedState(f));
    private readonly Dictionary<string, FileHashes> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ThreatMatch> _matches = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private readonly SemaphoreSlim _sweepSignal = new(0, 1);
    private ThreatIndex _index = ThreatIndex.Empty;
    private IpOriginDatabase? _origins;
    private IReadOnlyList<LolbinObservation> _lolbins = [];
    private IReadOnlyList<RemoteConnectionOrigin> _connections = [];
    private ThreatDatabaseCoverage _coverage = new(0, 0, 0, 0, null, null);
    private readonly List<string> _warnings = [];
    private DateTimeOffset _lastManualRefresh = DateTimeOffset.MinValue;

    private sealed class FeedState(ThreatFeedDefinition definition)
    {
        public ThreatFeedDefinition Definition { get; } = definition;
        public ParsedThreatFeed? Parsed { get; set; }
        public DateTimeOffset? RetrievedAtUtc { get; set; }
        public DateTimeOffset? LastAttemptUtc { get; set; }
        public long Bytes { get; set; }
        public string? Error { get; set; }
        public bool Updating { get; set; }

        public bool IsDue(DateTimeOffset now) =>
            !Updating && (RetrievedAtUtc is not { } retrieved || now - retrieved >= Definition.RefreshInterval) &&
            (Error is null || LastAttemptUtc is not { } attempt || now - attempt >= RetryAfterFailure);
    }

    private sealed record FileHashes(long Length, DateTime LastWriteUtc, string Sha256, string Sha1, string Md5);

    public ThreatIndex Index => Volatile.Read(ref _index);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _ = Task.Run(() => ServePipeAsync(stoppingToken), stoppingToken);
        // A damaged cache or an unexpected error on one PC must never stop the service (and every other sensor with it).
        try { await Task.Run(LoadCaches, stoppingToken); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Saved threat databases could not be loaded; they will be downloaded again.");
        }
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (settings.Current.ThreatDatabases) await RefreshDueAsync(force: false, stoppingToken);
                await SweepAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Threat database cycle failed.");
            }
            try { await _sweepSignal.WaitAsync(SweepInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal void LoadCaches()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var state in _feeds.Values)
        {
            try
            {
                if (_cache.TryRead(state.Definition, now) is not { } cached) continue;
                var parsed = ThreatFeedParser.Parse(state.Definition, cached.Payload);
                lock (_gate)
                {
                    state.Parsed = parsed;
                    state.RetrievedAtUtc = cached.RetrievedAtUtc;
                    state.Bytes = cached.Payload.Length;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Any per-database failure (damaged file, low memory, unexpected content) only affects that database.
                lock (_gate) state.Error = Bound("The saved copy could not be used: " + ex.Message, 200);
                logger.LogWarning(ex, "Saved copy of {Feed} could not be used.", state.Definition.Id);
            }
        }
        Rebuild();
    }

    internal async Task<int> RefreshDueAsync(bool force, CancellationToken token)
    {
        if (!await _refreshLock.WaitAsync(0, token)) return 0;
        var updated = 0;
        try
        {
            foreach (var state in _feeds.Values)
            {
                var now = DateTimeOffset.UtcNow;
                lock (_gate)
                {
                    if (!(force ? !state.Updating && (state.Error is not null || state.RetrievedAtUtc is null || now - state.RetrievedAtUtc >= TimeSpan.FromMinutes(30)) : state.IsDue(now))) continue;
                    state.Updating = true;
                    state.LastAttemptUtc = now;
                }
                try
                {
                    var payload = await _downloader.FetchAsync(state.Definition, token);
                    var parsed = await Task.Run(() => ThreatFeedParser.Parse(state.Definition, payload), token);
                    var retrieved = DateTimeOffset.UtcNow;
                    try { _cache.Write(state.Definition, payload, retrieved); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        logger.LogWarning(ex, "Could not save {Feed}.", state.Definition.Id);
                    }
                    lock (_gate)
                    {
                        state.Parsed = parsed;
                        state.RetrievedAtUtc = retrieved;
                        state.Bytes = payload.Length;
                        state.Error = null;
                    }
                    updated++;
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    // Every failure stays with its own database (network, TLS, proxy, content, memory) and is retried later.
                    lock (_gate) state.Error = ex is OperationCanceledException ? "The download stalled or timed out; it will be retried."
                        : Bound(DescribeFailure(ex), 200);
                    logger.LogInformation("Threat database {Feed} was not updated: {Reason}", state.Definition.Id, ex.Message);
                }
                finally
                {
                    lock (_gate) state.Updating = false;
                }
            }
            if (updated > 0) await Task.Run(Rebuild, token);
        }
        finally
        {
            _refreshLock.Release();
        }
        return updated;
    }

    private void Rebuild()
    {
        List<(ThreatFeedDefinition, ParsedThreatFeed)> loaded;
        IpOriginDatabase? origins;
        lock (_gate)
        {
            loaded = _feeds.Values.Where(s => s.Parsed is not null).Select(s => (s.Definition, s.Parsed!)).ToList();
            origins = _feeds["ip-origin"].Parsed?.Origins;
        }
        Volatile.Write(ref _index, ThreatIndex.Build(loaded));
        Volatile.Write(ref _origins, origins);
    }

    internal async Task SweepAsync(CancellationToken token)
    {
        var started = Stopwatch.StartNew();
        var index = Index;
        var origins = Volatile.Read(ref _origins);
        var now = DateTimeOffset.UtcNow;
        var found = new List<ThreatMatch>();
        var cleared = new List<SecurityFindingObservation>();
        var warnings = new List<string>();

        // Connections, with the program that owns each one.
        var connections = await Task.Run(() => TcpTable.Capture(warnings), token);
        var processNames = ProcessNames();
        var processPaths = ProcessImages().GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First().Path);
        var origin = new List<RemoteConnectionOrigin>();
        var connectedBy = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var connection in connections.Where(c => c.State == TcpTable.Established).Take(MaximumConnections))
        {
            if (ThreatFeedParser.IsReserved(connection.Remote)) continue;
            var program = processNames.GetValueOrDefault(connection.ProcessId, connection.ProcessId == 4 ? "System" : $"PID {connection.ProcessId}");
            var remote = connection.Remote.IsIPv4MappedToIPv6 ? connection.Remote.MapToIPv4().ToString() : connection.Remote.ToString();
            connectedBy.TryAdd(remote, program);
            var hits = index.Lookup(new ThreatIndicator(IndicatorType.Ip, remote, ""));
            var where = origins?.Lookup(connection.Remote);
            if (hits.Count > 0)
            {
                var path = processPaths.GetValueOrDefault(connection.ProcessId);
                var evidence = new ThreatEvidence(ThreatMatchPlaces.Connection, remote, hits, program, path, RemotePort: connection.RemotePort,
                    Network: where?.Asn is { } asn ? $"AS{asn} {where.Network} ({where.CountryCode ?? "??"})" : null);
                found.Add(Assess(now, evidence, $"{program} → {remote}:{connection.RemotePort}"));
            }
            origin.Add(new RemoteConnectionOrigin(Bound(program, 128), connection.ProcessId, remote, connection.RemotePort,
                where?.CountryCode, where?.Asn, where?.Network, hits.Count > 0));
        }

        // DNS cache names, attributed to a program when one is connected to an address the name resolved to.
        var domains = 0;
        try
        {
            var snapshot = await Task.Run(dns.Capture, token);
            foreach (var entry in snapshot.Entries)
            {
                if (!ThreatFeedParser.TryClassify(entry.Domain, out var indicator) || indicator.Type != IndicatorType.Domain) continue;
                domains++;
                // Shared platforms and SDK hosts are no longer indexed; retire any alert raised before that rule existed.
                if (SharedPlatforms.IsSharedPlatform(indicator.Value))
                    foreach (var feed in ThreatFeedCatalog.All.Where(f => f.Kind is ThreatFeedKinds.Domain or ThreatFeedKinds.Mixed))
                        cleared.Add(SecurityFindingMapper.Create(SecurityFindingCatalog.ThreatDatabase, ThreatMatchPlaces.Dns, "LOW", feed.Technique,
                            "Not a threat: shared service also used by ordinary apps", $"{feed.Id}:{indicator.Value}"));
                var hits = index.Lookup(indicator);
                if (hits.Count == 0) continue;
                var addresses = DnsCacheResolver.CachedAddresses(indicator.Value);
                var connected = addresses.Select(a => connectedBy.GetValueOrDefault(a)).FirstOrDefault(p => p is not null);
                var network = addresses.Select(a => System.Net.IPAddress.TryParse(a, out var ip) ? origins?.Lookup(ip) : null)
                    .FirstOrDefault(o => o?.Asn is not null);
                var sinkholed = addresses.Count > 0 && addresses.All(IsSinkhole);
                var evidence = new ThreatEvidence(ThreatMatchPlaces.Dns, indicator.Value, hits, ConnectionObserved: connected is not null,
                    ConnectedProgram: connected, ParentDomainOnly: !ListsExactName(index, indicator.Value),
                    Network: network is { } n ? $"AS{n.Asn} {n.Network} ({n.CountryCode ?? "??"})" : null, Sinkholed: sinkholed);
                var resolved = addresses.Count > 0 ? $" ({string.Join(", ", addresses.Take(3))})" : "";
                found.Add(Assess(now, evidence, connected is not null
                    ? $"{connected} connected to {indicator.Value}{resolved}"
                    : $"This PC looked up {indicator.Value}{resolved}"));
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception or UnauthorizedAccessException)
        {
            warnings.Add("The DNS cache could not be read.");
        }

        // Loaded kernel drivers against LOLDrivers (and every hash feed); hits are signature-checked.
        var driverCount = 0;
        var driverSnapshot = await Task.Run(drivers.Capture, token);
        foreach (var driver in driverSnapshot.Drivers)
        {
            token.ThrowIfCancellationRequested();
            if (DriverPath(driver.ImagePath) is not { } path || Hash(path) is not { } hashes) continue;
            driverCount++;
            var hits = HashHits(index, hashes).ToArray();
            if (hits.Length == 0) continue;
            var (signed, signer) = Signature(path);
            found.Add(Assess(now, new ThreatEvidence(ThreatMatchPlaces.Driver, hashes.Sha256, hits, driver.Name, path, signed, signer), $"{driver.Name} ({path})"));
        }

        // Running programs outside the Windows folder against malware hash feeds; LOLBins as context.
        var programs = 0;
        var lolbins = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
        foreach (var (pid, path) in processPaths.Select(p => (p.Key, p.Value)).DistinctBy(p => p.Value, StringComparer.OrdinalIgnoreCase).Take(MaximumProgramsPerSweep))
        {
            token.ThrowIfCancellationRequested();
            var name = Path.GetFileName(path);
            if (index.Lolbin(name) is not null) lolbins[name] = lolbins.GetValueOrDefault(name) + 1;
            if (path.StartsWith(windows, StringComparison.OrdinalIgnoreCase) || Hash(path) is not { } hashes) continue;
            programs++;
            var hits = HashHits(index, hashes).ToArray();
            if (hits.Length == 0) continue;
            var (signed, signer) = Signature(path);
            found.Add(Assess(now, new ThreatEvidence(ThreatMatchPlaces.Program, hashes.Sha256, hits, name, path, signed, signer), $"{name} (PID {pid}, {path})"));
        }

        var newFindings = new List<SecurityFindingObservation>();
        lock (_gate)
        {
            foreach (var match in found)
            {
                var key = $"{match.Where}\0{match.Indicator}";
                // A finding is (re)reported when first seen or when its assessment changes, so severities stay current.
                if (!_matches.TryGetValue(key, out var previous) || previous.Verdict != match.Verdict || previous.Severity != match.Severity)
                    newFindings.Add(SecurityFindingMapper.Create(SecurityFindingCatalog.ThreatDatabase, match.Where, match.Severity, match.Technique,
                        $"{ThreatVerdicts.Label(match.Verdict)} ({match.Confidence}%): {match.Label} — {match.Subject}",
                        $"{match.FeedId.Split(',')[0]}:{match.Indicator}"));
                _matches[key] = match;
            }
            foreach (var stale in _matches.Where(m => now - m.Value.SeenAtUtc > TimeSpan.FromDays(7)).Select(m => m.Key).ToList()) _matches.Remove(stale);
            if (_matches.Count > MaximumMatches)
                foreach (var old in _matches.OrderBy(m => m.Value.SeenAtUtc).Take(_matches.Count - MaximumMatches).Select(m => m.Key).ToList()) _matches.Remove(old);
            _lolbins = lolbins.Select(l => index.Lolbin(l.Key) is { } info ? new LolbinObservation(Bound(l.Key, 64), info.Categories, info.Techniques, l.Value) : null)
                .OfType<LolbinObservation>().OrderBy(l => l.Name).Take(64).ToArray();
            _connections = origin.OrderByDescending(c => c.Listed).ThenBy(c => c.Program).Take(MaximumConnections).ToArray();
            _coverage = new ThreatDatabaseCoverage(origin.Count, domains, driverCount, programs, now, started.Elapsed);
            _warnings.Clear();
            _warnings.AddRange(warnings.Take(16));
        }
        if (newFindings.Count > 0)
        {
            foreach (var finding in newFindings.Where(f => f.Severity is "HIGH" or "CRITICAL")) logger.LogWarning("Threat database match: {Summary}", finding.Summary);
            await alerts.IngestFindingsAsync(newFindings.Take(SecurityAlertRepository.MaximumFindingsPerIngest).ToArray(), now, token);
        }
        // Matches the verification engine cleared (already blocked by this PC) and shared-service hosts are retired.
        cleared.AddRange(found.Where(m => ThreatVerdicts.IsCleared(m.Verdict)).Select(m => SecurityFindingMapper.Create(SecurityFindingCatalog.ThreatDatabase,
            m.Where, m.Severity, m.Technique, $"{ThreatVerdicts.Label(m.Verdict)}: {m.Label} — {m.Subject}", $"{m.FeedId.Split(',')[0]}:{m.Indicator}")));
        await RetireAsync(cleared, token);
    }

    /// <summary>Suppresses open threat-database alerts that verification has shown are not threats (state changes are audited).</summary>
    private async Task RetireAsync(IReadOnlyList<SecurityFindingObservation> cleared, CancellationToken token)
    {
        if (cleared.Count == 0) return;
        var identities = cleared.Select(SecurityFindingMapper.Identity).ToHashSet(StringComparer.Ordinal);
        SecurityAlertSnapshot snapshot;
        try { snapshot = await alerts.ReadSnapshotAsync(token); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException) { return; }
        foreach (var alert in snapshot.Alerts.Where(a => a.LogName == SecurityFindingCatalog.ThreatDatabase && a.State is "Open" or "Acknowledged" && identities.Contains(a.Provider)))
        {
            var response = await alerts.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, alert.State, "Suppressed"), token);
            if (response.Accepted) logger.LogInformation("Retired cleared threat-database alert {Title}", alert.Title);
        }
    }

    private static bool IsSinkhole(string address) =>
        System.Net.IPAddress.TryParse(address, out var ip) && (ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any) ||
                                                              System.Net.IPAddress.IsLoopback(ip));

    private static bool ListsExactName(ThreatIndex index, string domain) =>
        index.LookupExact(domain).Count > 0;

    private static ThreatMatch Assess(DateTimeOffset now, ThreatEvidence evidence, string subject)
    {
        var assessment = ThreatVerdictEngine.Assess(evidence);
        var feeds = evidence.Hits.Select(h => h.Feed).DistinctBy(f => f.Id)
            .OrderBy(f => ThreatFeedCatalog.All.ToList().IndexOf(f)).ToArray();
        var label = evidence.Hits.Select(h => h.Label).OrderByDescending(l => l.Length).First();
        return new ThreatMatch(now, evidence.Place, Bound(evidence.Indicator, 128), Bound(subject, 300),
            Bound(string.Join(",", feeds.Select(f => f.Id)), 128), Bound(string.Join(", ", feeds.Select(f => f.Name)), 200),
            Bound(label, 96), assessment.Severity, feeds[0].Technique is { Length: > 0 } technique ? technique : "T1071",
            assessment.Verdict, assessment.Confidence, assessment.Reasons.Select(r => Bound(r, 300)).Take(12).ToArray());
    }

    /// <summary>Authenticode check for a matched file: embedded signature (with signer) or a Windows catalog signature.</summary>
    private (bool? Signed, string? Signer) Signature(string path)
    {
        try
        {
            if (AuthenticodeVerifier.VerifyEmbeddedSignature(path, out var signer)) return (true, signer);
            if (signatures?.IsMicrosoftSigned(path) == true) return (true, "Microsoft (catalog)");
            return (false, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return (null, null);
        }
    }

    private static IEnumerable<(ThreatFeedDefinition, string)> HashHits(ThreatIndex index, FileHashes hashes) =>
        index.Lookup(new ThreatIndicator(IndicatorType.Sha256, hashes.Sha256, ""))
            .Concat(index.Lookup(new ThreatIndicator(IndicatorType.Sha1, hashes.Sha1, "")))
            .Concat(index.Lookup(new ThreatIndicator(IndicatorType.Md5, hashes.Md5, "")))
            .DistinctBy(h => h.Item1.Id);

    /// <summary>Hashes a file once per (length, write time); a changed file is hashed again.</summary>
    private FileHashes? Hash(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length == 0 || info.Length > MaximumHashedFileBytes || (info.Attributes & FileAttributes.ReparsePoint) != 0) return null;
            lock (_gate)
                if (_hashes.TryGetValue(path, out var known) && known.Length == info.Length && known.LastWriteUtc == info.LastWriteTimeUtc) return known;
            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 128 * 1024, FileOptions.SequentialScan))
            {
                var buffer = new byte[128 * 1024];
                int read;
                while ((read = stream.Read(buffer)) > 0)
                {
                    sha256.AppendData(buffer, 0, read);
                    sha1.AppendData(buffer, 0, read);
                    md5.AppendData(buffer, 0, read);
                }
            }
            var hashes = new FileHashes(info.Length, info.LastWriteTimeUtc,
                Convert.ToHexStringLower(sha256.GetHashAndReset()), Convert.ToHexStringLower(sha1.GetHashAndReset()), Convert.ToHexStringLower(md5.GetHashAndReset()));
            lock (_gate)
            {
                if (_hashes.Count > 4096) _hashes.Clear();
                _hashes[path] = hashes;
            }
            return hashes;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>Turns kernel image names (\SystemRoot\..., \??\C:\..., System32\...) into a local path, or null.</summary>
    internal static string? DriverPath(string imagePath)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        var path = imagePath.Replace('/', '\\');
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = windows + path[11..];
        else if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) path = windows + "\\" + path;
        else if (path.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase)) path = Path.GetPathRoot(windows)!.TrimEnd('\\') + path;
        if (path.Length > 260 || path.Contains("..", StringComparison.Ordinal) || !Path.IsPathFullyQualified(path)) return null;
        return path;
    }

    private static Dictionary<int, string> ProcessNames()
    {
        var names = new Dictionary<int, string>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { names[process.Id] = process.ProcessName + ".exe"; }
                catch (InvalidOperationException) { }
            }
        }
        return names;
    }

    private static IEnumerable<(int Pid, string Path)> ProcessImages()
    {
        foreach (var process in Process.GetProcesses())
        {
            string? path = null;
            var pid = process.Id;
            using (process)
            {
                if (pid <= 4) continue;
                using var handle = OpenProcess(0x1000, false, (uint)pid); // PROCESS_QUERY_LIMITED_INFORMATION
                if (!handle.IsInvalid)
                {
                    var buffer = new char[1024];
                    var size = (uint)buffer.Length;
                    if (QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0) path = new string(buffer, 0, (int)size);
                }
            }
            if (path is not null && Path.IsPathFullyQualified(path)) yield return (pid, path);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);

    public ThreatDatabaseSnapshot Snapshot()
    {
        var now = DateTimeOffset.UtcNow;
        var index = Index;
        lock (_gate)
        {
            var enabled = settings.Current.ThreatDatabases;
            var feeds = _feeds.Values.Select(s =>
            {
                var d = s.Definition;
                var state = s.Updating ? ThreatFeedStates.Updating
                    : s.Parsed is null ? (s.Error is not null ? ThreatFeedStates.Failed : enabled ? ThreatFeedStates.NotLoaded : ThreatFeedStates.Disabled)
                    : s.RetrievedAtUtc is { } r && now - r > d.RefreshInterval * 2 ? ThreatFeedStates.Stale
                    : s.Error is not null ? ThreatFeedStates.Stale : ThreatFeedStates.Current;
                return new ThreatFeedStatus(d.Id, d.Name, d.Provider, d.Kind, d.Purpose, d.License, d.Homepage, state, s.Parsed?.Entries ?? 0,
                    s.RetrievedAtUtc, s.RetrievedAtUtc + d.RefreshInterval, s.Bytes, s.Error is null ? null : Bound(s.Error, 300));
            }).ToArray();
            var warnings = _warnings.Select(w => Bound(w, 500)).ToList();
            if (!enabled) warnings.Insert(0, "Database updates are switched off in Settings. Saved copies are still used until they expire.");
            return new ThreatDatabaseSnapshot(1, now, enabled, index.IndicatorCount, feeds,
                _matches.Values.OrderByDescending(m => SeverityRank(m.Severity)).ThenByDescending(m => m.SeenAtUtc).Take(200).ToArray(),
                _lolbins, _coverage, _connections.Take(250).ToArray(), warnings);
        }
    }

    private static int SeverityRank(string severity) => severity switch { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, _ => 1 };

    internal async Task<ThreatDatabaseResponse> HandleAsync(ThreatDatabaseRequest? request, CancellationToken token)
    {
        if (request is not { SchemaVersion: 1 } || request.Operation is null)
            return new(1, false, "invalid-request", null, null, null, null);
        switch (request.Operation)
        {
            case ThreatDatabaseOperations.Snapshot when request.Value is null:
                return new(1, true, "snapshot", Snapshot(), null, null, null);
            case ThreatDatabaseOperations.Refresh when request.Value is null:
                if (!settings.Current.ThreatDatabases) return new(1, false, "disabled", Snapshot(), null, null, null);
                lock (_gate)
                {
                    if (DateTimeOffset.UtcNow - _lastManualRefresh < ManualRefreshCooldown) return new(1, false, "cooldown", Snapshot(), null, null, null);
                    _lastManualRefresh = DateTimeOffset.UtcNow;
                }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await RefreshDueAsync(force: true, token);
                        if (_sweepSignal.CurrentCount == 0) _sweepSignal.Release();
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogWarning(ex, "Manual threat database refresh failed."); }
                    catch (OperationCanceledException) { }
                }, token);
                return new(1, true, "refresh-started", Snapshot(), null, null, null);
            case ThreatDatabaseOperations.Lookup when request.Value is { Length: > 0 and <= 2048 } value && !value.Any(char.IsControl):
            {
                var candidate = value.Trim();
                if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https") candidate = uri.IdnHost;
                if (!ThreatFeedParser.TryClassify(candidate, out var indicator) || indicator.Type is IndicatorType.Network)
                    return new(1, false, "unrecognized", null, null, null, null);
                var hits = Index.Lookup(indicator).Select(h => new ThreatLookupHit(h.Feed.Id, h.Feed.Name, h.Label)).Take(32).ToArray();
                var originInfo = indicator.Type == IndicatorType.Ip && IPAddress.TryParse(indicator.Value, out var address) ? Volatile.Read(ref _origins)?.Lookup(address) : null;
                return new(1, true, "lookup", null, indicator.Type.ToString().ToLowerInvariant(), indicator.Value, hits, originInfo);
            }
            case ThreatDatabaseOperations.Browse when request.FeedId is { } feedId && _feeds.TryGetValue(feedId, out var state) &&
                                                      request.Value is null or { Length: <= 128 } && request.Value?.Any(char.IsControl) != true:
            {
                ParsedThreatFeed? parsed;
                lock (_gate) parsed = state.Parsed;
                if (parsed is null) return new(1, true, "browse", null, null, null, null, Browse: [], BrowseTotal: 0);
                var query = request.Value?.Trim() ?? "";
                var rows = parsed.Indicators.Select(i => new ThreatBrowseRow(i.Value, TypeName(i.Type), i.Label))
                    .Concat(parsed.Lolbins.Select(l => new ThreatBrowseRow(l.Name, "built-in tool", $"{l.Categories} ({l.Techniques})")))
                    .Where(r => query.Length == 0 || r.Value.Contains(query, StringComparison.OrdinalIgnoreCase) || r.Label.Contains(query, StringComparison.OrdinalIgnoreCase));
                var total = 0;
                var page = new List<ThreatBrowseRow>(MaximumBrowseRows);
                foreach (var row in rows)
                {
                    total++;
                    if (page.Count < MaximumBrowseRows) page.Add(row);
                }
                return new(1, true, "browse", null, null, null, null, Browse: page, BrowseTotal: total);
            }
            default:
                return new(1, false, "invalid-request", null, null, null, null);
        }
    }

    private const int MaximumBrowseRows = 500;

    private static string TypeName(IndicatorType type) => type switch
    {
        IndicatorType.Ip => "IP address", IndicatorType.Network => "network", IndicatorType.Domain => "domain",
        IndicatorType.Sha256 => "SHA-256", IndicatorType.Sha1 => "SHA-1", IndicatorType.Md5 => "MD5", _ => "entry",
    };

    private async Task ServePipeAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough, 4096, 64 * 1024, PipeSecurityFactory.CreateCurrentUserReadSecurity());
                await pipe.WaitForConnectionAsync(stoppingToken);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                var lengthBytes = new byte[4];
                await pipe.ReadExactlyAsync(lengthBytes, timeout.Token);
                var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
                if (length is <= 0 or > 4096) throw new InvalidDataException("The request length is outside its limit.");
                var body = new byte[length];
                await pipe.ReadExactlyAsync(body, timeout.Token);
                ThreatDatabaseRequest? request;
                try { request = BoundedJson.Deserialize<ThreatDatabaseRequest>(body); }
                catch (Exception ex) when (ex is Newtonsoft.Json.JsonException or InvalidDataException) { request = null; }
                var response = await HandleAsync(request, timeout.Token);
                var payload = BoundedJson.Serialize(response);
                if (payload.Length > BoundedJson.MaximumPayloadBytes) payload = BoundedJson.Serialize(response with { Snapshot = response.Snapshot! with { Connections = [], Matches = response.Snapshot.Matches.Take(50).ToArray() } });
                BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, payload.Length);
                await pipe.WriteAsync(lengthBytes, timeout.Token);
                await pipe.WriteAsync(payload, timeout.Token);
                await pipe.FlushAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or InvalidOperationException or Newtonsoft.Json.JsonException)
            {
                logger.LogDebug(ex, "A threat database client disconnected or sent an invalid request.");
            }
        }
    }

    /// <summary>A short, actionable reason for a failed download (the innermost message is usually the useful one).</summary>
    internal static string DescribeFailure(Exception ex)
    {
        var inner = ex;
        while (inner.InnerException is { } next) inner = next;
        return inner switch
        {
            System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.HostNotFound } => "The source's address could not be resolved (no internet, DNS filtering or a blocked domain).",
            System.Net.Sockets.SocketException => $"Could not connect to the source ({inner.Message}). A firewall, VPN or proxy may be blocking it.",
            System.Security.Authentication.AuthenticationException => "The secure connection failed (a network filter or proxy may be intercepting HTTPS, or the PC clock is wrong).",
            OutOfMemoryException => "Not enough free memory to load this database right now.",
            _ => ex is HttpRequestException && inner != ex ? $"{ex.Message} {inner.Message}" : ex.Message,
        };
    }

    private static string Bound(string value, int max)
    {
        var clean = new string(value.Where(c => !char.IsControl(c)).ToArray());
        return clean.Length <= max ? clean : clean[..(max - 1)] + "…";
    }
}

/// <summary>IPv4 and IPv6 TCP table with owning process IDs (GetExtendedTcpTable, documented iphlpapi API).</summary>
internal static class TcpTable
{
    public const int Established = 5;

    public sealed record Row(IPAddress Remote, int RemotePort, int State, int ProcessId);

    public static IReadOnlyList<Row> Capture(List<string> warnings)
    {
        var rows = new List<Row>();
        Read(2, rows, warnings);  // AF_INET
        Read(23, rows, warnings); // AF_INET6
        return rows;
    }

    private static void Read(int family, List<Row> rows, List<string> warnings)
    {
        var size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
        if (size <= 0 || size > 32 * 1024 * 1024) return;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var result = GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);
            if (result != 0)
            {
                warnings.Add($"Windows did not return the {(family == 2 ? "IPv4" : "IPv6")} connection table (error {result}).");
                return;
            }
            var count = Marshal.ReadInt32(buffer);
            var rowSize = family == 2 ? 24 : 56;
            if (count < 0 || 4 + (long)count * rowSize > size) return;
            for (var i = 0; i < count && rows.Count < 20_000; i++)
            {
                var row = buffer + 4 + i * rowSize;
                if (family == 2)
                {
                    var state = Marshal.ReadInt32(row);
                    var remote = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(row + 12)));
                    var port = Port(Marshal.ReadInt32(row + 16));
                    rows.Add(new Row(remote, port, state, Marshal.ReadInt32(row + 20)));
                }
                else
                {
                    var bytes = new byte[16];
                    Marshal.Copy(row + 24, bytes, 0, 16);
                    var scope = (uint)Marshal.ReadInt32(row + 40);
                    var port = Port(Marshal.ReadInt32(row + 44));
                    var state = Marshal.ReadInt32(row + 48);
                    rows.Add(new Row(new IPAddress(bytes, scope), port, state, Marshal.ReadInt32(row + 52)));
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int Port(int raw) => (ushort)IPAddress.NetworkToHostOrder((short)(raw & 0xFFFF));

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
}
