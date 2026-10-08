using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Verifies the action audit chain at start and every ten minutes. A broken chain becomes a CRITICAL triage finding
/// (T1070, indicator removal); the latest result is written to state\audit-verification.v1.json for the case file.
/// The status file is informational; the protection is the keyed chain itself.
/// </summary>
public sealed class AuditIntegrityMonitor(ActionAuditLog audit, SecurityAlertRepository alerts, ILogger<AuditIntegrityMonitor> logger,
    string? statusPath = null) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(10);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private string? _lastProblem;

    public static string DefaultStatusPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state", "audit-verification.v1.json");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await CheckOnceAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "The audit integrity check failed to run.");
            }
            try { await Task.Delay(Interval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal async Task<AuditVerification> CheckOnceAsync(CancellationToken token)
    {
        var result = await Task.Run(audit.Verify, token);
        try
        {
            var path = statusPath ?? DefaultStatusPath();
            File.WriteAllText(path, JsonSerializer.Serialize(new { checkedAtUtc = DateTimeOffset.UtcNow, result.Intact, result.Chained, result.Legacy, result.LastSequence, result.Message }, Json));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }

        if (!result.Intact && result.Message != _lastProblem)
        {
            logger.LogError("Action audit log integrity failure: {Message}", result.Message);
            var finding = SecurityFindingMapper.Create(SecurityFindingCatalog.Integrity, "Audit log", "CRITICAL", "T1070",
                "Downpour's action audit log was altered or truncated", result.Message);
            await alerts.IngestFindingsAsync([finding], DateTimeOffset.UtcNow, token);
        }
        _lastProblem = result.Intact ? null : result.Message;
        return result;
    }
}
