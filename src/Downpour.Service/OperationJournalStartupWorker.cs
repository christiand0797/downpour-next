namespace Downpour.Service;

/// <summary>Applies journal schema migrations before the service reports healthy operation.</summary>
public sealed class OperationJournalStartupWorker(OperationJournal journal, ILogger<OperationJournalStartupWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await journal.InitializeAsync(stoppingToken);
        logger.LogInformation("Operation journal schema v{SchemaVersion} is ready; no response actions are enabled.", OperationJournal.CurrentSchemaVersion);
        try { await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}
