using Downpour.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>
/// Writes one summary per ISO week, from stored counts only. It is a start-time check plus a six-hour recheck rather than
/// a midnight timer, so a long-running session gets the week's file at the next check and a stopped machine writes it
/// when it next starts. Nothing is emailed and nothing leaves the PC.
/// </summary>
public sealed class WeeklyDigestWorker(
    SecurityAlertRepository repository,
    WeeklyDigestWriter writer,
    ILogger<WeeklyDigestWorker> logger) : BackgroundService
{
    public static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan Interval = TimeSpan.FromHours(6);
    /// <summary>A digest is only written once the store has watched a full week, so a fresh install is not called quiet.</summary>
    public static readonly TimeSpan MinimumWindow = TimeSpan.FromDays(7);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TryWriteAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "The weekly summary could not be written; it will be retried.");
            }

            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    internal async Task<bool> TryWriteAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (writer.ExistsFor(now)) return false;

        var since = now - MinimumWindow;
        var facts = await repository.ReadWeeklyDigestFactsAsync(since, cancellationToken);
        if (facts.ObservedSinceUtc is not { } observed || now - observed < MinimumWindow)
        {
            logger.LogDebug("The weekly summary is deferred until the alert store has watched a full week.");
            return false;
        }

        var markdown = WeeklyDigest.Build(WeeklyDigestInputs.FromFacts(facts, since, now));
        var path = writer.Write(now, markdown);
        logger.LogInformation("Weekly summary written to {Path}.", path);
        return true;
    }
}
