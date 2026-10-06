using System.Threading.Channels;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>
/// Runs Sigma rules and AMSI over PowerShell script-block text (Event 4104) and stores detections as findings.
/// The subscription exists only while the owner-approved "script-block analysis" setting is on (SECURITY.md). Script
/// text stays in this process's memory: findings carry only the rule title, severity, technique, and a record-based ID.
/// </summary>
public sealed class SigmaAmsiPushWorker(
    SensorSettingsStore settings,
    SecurityAlertRepository alerts,
    SecurityAlertSnapshotStore alertSnapshots,
    ILogger<SigmaAmsiPushWorker> logger,
    ILogger<SigmaAmsiEventProcessor> processorLogger) : BackgroundService
{
    private const int QueueCapacity = 256;
    private const int MaximumBatchSize = 64;
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromMilliseconds(150);
    private readonly object _subscriptionGate = new();
    private IDisposable? _subscription;
    private long _dropped;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = Channel.CreateBounded<ScriptBlock>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        });
        var processor = new SigmaAmsiEventProcessor(processorLogger);

        void Apply(SensorSettingsSnapshot current)
        {
            lock (_subscriptionGate)
            {
                if (current.ScriptBlockAnalysis && _subscription is null)
                {
                    _subscription = ScriptBlockSource.Subscribe(
                        block => { if (!channel.Writer.TryWrite(block)) Interlocked.Increment(ref _dropped); },
                        warning => logger.LogWarning("{Warning}", warning));
                    logger.LogInformation("PowerShell script-block analysis {State}.", _subscription is null ? "could not start" : "is on");
                }
                else if (!current.ScriptBlockAnalysis && _subscription is not null)
                {
                    _subscription.Dispose();
                    _subscription = null;
                    logger.LogInformation("PowerShell script-block analysis is off; the subscription was closed.");
                }
            }
        }

        settings.Changed += Apply;
        try
        {
            Apply(settings.Current);
            try
            {
                await alerts.InitializeAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Sigma/AMSI worker started, but persistent alert storage is not ready.");
            }

            while (await channel.Reader.WaitToReadAsync(stoppingToken))
            {
                await Task.Delay(CoalesceWindow, stoppingToken);
                var batch = new List<ScriptBlock>(MaximumBatchSize);
                while (batch.Count < MaximumBatchSize && channel.Reader.TryRead(out var block))
                    batch.Add(block);
                // Blocks queued just before the setting was turned off are discarded unanalyzed.
                if (batch.Count == 0 || !settings.Current.ScriptBlockAnalysis) continue;

                try
                {
                    var findings = batch
                        .SelectMany(processor.ProcessScriptBlock)
                        .Select(ToFinding)
                        .Take(SecurityAlertRepository.MaximumFindingsPerIngest)
                        .ToArray();
                    if (findings.Length > 0)
                    {
                        await alerts.IngestFindingsAsync(findings, DateTimeOffset.UtcNow, stoppingToken);
                        alertSnapshots.Publish(await alerts.ReadSnapshotAsync(stoppingToken));
                    }
                    var dropped = Interlocked.Exchange(ref _dropped, 0);
                    if (dropped > 0) logger.LogWarning("{Dropped} PowerShell script blocks were dropped because the analysis queue was full.", dropped);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "Sigma/AMSI processing failed for a batch; detections in it were not stored.");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            settings.Changed -= Apply;
            lock (_subscriptionGate)
            {
                _subscription?.Dispose();
                _subscription = null;
            }
        }
    }

    /// <summary>Maps a processor detection to a finding; the processor's alert ID (rule + event record) is the identity.</summary>
    internal static SecurityFindingObservation ToFinding(SecurityAlert detection)
    {
        var amsi = detection.Title.StartsWith("AMSI", StringComparison.Ordinal);
        return SecurityFindingMapper.Create(
            amsi ? SecurityFindingCatalog.Amsi : SecurityFindingCatalog.Sigma,
            amsi ? "AMSI" : "Sigma rule",
            SecurityFindingCatalog.Severities.Contains(detection.Severity) ? detection.Severity : "MEDIUM",
            detection.Technique,
            detection.Title,
            detection.AlertId.ToLowerInvariant());
    }
}
