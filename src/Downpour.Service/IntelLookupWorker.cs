using System.Net;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Automatically looks up indicators from open alerts with the services the user configured (owner decision, SECURITY.md).
/// Only public IPs, hashes, and DNS-flagged domains are sent; lookups are rate-limited, cached for 24 hours, and logged
/// without indicator values. Malicious or suspicious verdicts become "Downpour/Intel" findings in triage.
/// </summary>
public sealed class IntelLookupWorker(
    SensorSettingsStore settings,
    IntelKeyStore keys,
    IntelResultStore store,
    SecurityAlertRepository alerts,
    ILogger<IntelLookupWorker> logger) : BackgroundService
{
    internal const int MaximumLookupsPerRun = 25;
    internal const int MaximumIndicatorsPerRun = 100;
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
    private readonly IntelRateLimiter _limiter = new();
    internal IntelLookupClient Client { get; init; } = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await alerts.InitializeAsync(stoppingToken);
            await Task.Delay(InitialDelay, stoppingToken);
            using var timer = new PeriodicTimer(Interval);
            do
            {
                try
                {
                    await RunOnceAsync(stoppingToken);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    logger.LogWarning(exception, "Intel lookup run failed.");
                    store.CompleteRun(DateTimeOffset.UtcNow, "Run failed; see the service log.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    internal async Task<int> RunOnceAsync(CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow;
        if (!settings.Current.IntelLookups)
        {
            store.CompleteRun(now, "Automatic lookups are off.");
            return 0;
        }
        var services = keys.ConfiguredServices;
        if (services.Count == 0)
        {
            store.CompleteRun(now, "No API keys are configured.");
            return 0;
        }

        var snapshot = await alerts.ReadSnapshotAsync(token);
        var indicators = snapshot.Alerts
            .Where(alert => alert.State is "Open" or "Acknowledged" && alert.LogName != SecurityFindingCatalog.Intel)
            .SelectMany(IntelIndicatorExtractor.FromAlert)
            .DistinctBy(indicator => (indicator.Kind, indicator.Value))
            .Take(MaximumIndicatorsPerRun)
            .ToArray();

        var sent = 0;
        var stopped = new HashSet<string>(StringComparer.Ordinal);
        foreach (var indicator in indicators)
        {
            foreach (var service in services)
            {
                if (sent >= MaximumLookupsPerRun) break;
                if (stopped.Contains(service) || !IntelProviders.Supports(service, indicator.Kind) || store.IsCached(service, indicator, now)) continue;
                if (!_limiter.TryAcquire(service, DateTimeOffset.UtcNow)) continue;
                if (keys.Get(service) is not { Length: > 0 } key) continue;

                sent++;
                try
                {
                    var (result, status) = await Client.LookupAsync(service, indicator, key, token);
                    store.Record(new IntelOutboundRecord(service, indicator.Kind, DateTimeOffset.UtcNow, Outcome(status, result)),
                        IntelStatus.IsCacheable(status) ? result : null);
                    if (IntelStatus.StopsService(status))
                    {
                        stopped.Add(service);
                        logger.LogWarning("{Service} returned HTTP {Status}; lookups to it are paused until the next run.", service, (int)status);
                    }
                }
                catch (Exception exception) when (exception is HttpRequestException or InvalidDataException or IOException
                    || (exception is OperationCanceledException && !token.IsCancellationRequested))
                {
                    store.Record(new IntelOutboundRecord(service, indicator.Kind, DateTimeOffset.UtcNow, "Network error"), null);
                }
            }
            if (sent >= MaximumLookupsPerRun) break;
        }

        var findings = store.Results(DateTimeOffset.UtcNow)
            .Where(result => result.Verdict is IntelVerdicts.Malicious or IntelVerdicts.Suspicious)
            .Select(ToFinding)
            .Take(SecurityAlertRepository.MaximumFindingsPerIngest)
            .ToArray();
        if (findings.Length > 0) await alerts.IngestFindingsAsync(findings, DateTimeOffset.UtcNow, token);
        store.CompleteRun(DateTimeOffset.UtcNow, $"{sent} lookup{(sent == 1 ? "" : "s")} sent, {findings.Length} flagged indicator{(findings.Length == 1 ? "" : "s")}.");
        return sent;
    }

    internal static SecurityFindingObservation ToFinding(IntelLookupResult result) =>
        SecurityFindingMapper.Create(
            SecurityFindingCatalog.Intel,
            result.Service,
            result.Verdict == IntelVerdicts.Malicious ? "HIGH" : "MEDIUM",
            "TA0011",
            $"{result.Indicator} flagged {result.Verdict.ToLowerInvariant()} by {result.Service}: {result.Summary}",
            $"intel:{result.Service}:{result.IndicatorKind}:{result.Indicator}");

    private static string Outcome(HttpStatusCode status, IntelLookupResult result) =>
        status == HttpStatusCode.OK ? result.Verdict : $"HTTP {(int)status}";
}

/// <summary>Per-service sliding-minute and daily limits, conservative for free API tiers.</summary>
internal sealed class IntelRateLimiter
{
    private static readonly IReadOnlyDictionary<string, (int PerMinute, int PerDay)> Limits = new Dictionary<string, (int, int)>
    {
        [IntelServices.VirusTotal] = (4, 450),
        [IntelServices.AbuseIpDb] = (30, 900),
        [IntelServices.GreyNoise] = (10, 45),
    };
    private readonly Dictionary<string, Queue<DateTimeOffset>> _minute = new();
    private readonly Dictionary<string, (DateOnly Day, int Count)> _daily = new();

    public bool TryAcquire(string service, DateTimeOffset now)
    {
        if (!Limits.TryGetValue(service, out var limit)) return false;
        lock (_minute)
        {
            var window = _minute.TryGetValue(service, out var queue) ? queue : _minute[service] = new Queue<DateTimeOffset>();
            while (window.Count > 0 && now - window.Peek() >= TimeSpan.FromMinutes(1)) window.Dequeue();
            var today = DateOnly.FromDateTime(now.UtcDateTime);
            var daily = _daily.TryGetValue(service, out var value) && value.Day == today ? value : (today, 0);
            if (window.Count >= limit.PerMinute || daily.Item2 >= limit.PerDay) return false;
            window.Enqueue(now);
            _daily[service] = (today, daily.Item2 + 1);
            return true;
        }
    }
}
