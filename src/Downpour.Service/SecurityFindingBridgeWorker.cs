using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Periodically records hardening, firewall and persistence findings in the alert store so they reach the
/// Threats / Possible Threats triage views (v29 bridged firmware and persistence alerts into its alert pipeline).
/// Each source is captured independently; one failing source does not block the others.
/// </summary>
public sealed class SecurityFindingBridgeWorker(
    SecurityAlertRepository alerts,
    HardeningPostureProvider hardening,
    FirewallInventoryProvider firewall,
    PersistenceInventoryProvider persistence,
    UsbInventoryProvider usb,
    WirelessInventoryProvider wireless,
    RemoteAccessProvider remoteAccess,
    ILogger<SecurityFindingBridgeWorker> logger) : BackgroundService
{
    internal static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan Interval = TimeSpan.FromMinutes(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await alerts.InitializeAsync(stoppingToken);
            await Task.Delay(InitialDelay, stoppingToken);
            using var timer = new PeriodicTimer(Interval);
            do
            {
                await BridgeOnceAsync(stoppingToken);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    internal async Task<int> BridgeOnceAsync(CancellationToken token)
    {
        var findings = new List<SecurityFindingObservation>();
        Collect("hardening", () => SecurityFindingMapper.FromHardening(hardening.Capture()), findings);
        Collect("firewall", () => SecurityFindingMapper.FromFirewall(firewall.Capture()), findings);
        Collect("persistence", () => SecurityFindingMapper.FromPersistence(persistence.Capture()), findings);
        Collect("usb", () => SecurityFindingMapper.FromUsb(usb.Capture()), findings);
        Collect("wireless", () => SecurityFindingMapper.FromWireless(wireless.Capture()), findings);
        Collect("remote access", () => SecurityFindingMapper.FromRemoteAccess(remoteAccess.Capture()), findings);
        var bounded = findings.Take(SecurityAlertRepository.MaximumFindingsPerIngest).ToArray();
        if (findings.Count > bounded.Length)
            logger.LogWarning("Finding bridge truncated {Total} findings to {Limit}.", findings.Count, bounded.Length);
        await alerts.IngestFindingsAsync(bounded, DateTimeOffset.UtcNow, token);
        return bounded.Length;
    }

    private void Collect(string source, Func<IEnumerable<SecurityFindingObservation>> capture, List<SecurityFindingObservation> findings)
    {
        try
        {
            findings.AddRange(capture());
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogWarning(exception, "The {Source} finding source failed; other sources are still recorded.", source);
        }
    }
}
