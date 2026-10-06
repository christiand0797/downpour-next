using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Maps read-only sensor findings into alert-store observations (v29 bridged firmware and persistence alerts into its alert pipeline).</summary>
public static class SecurityFindingMapper
{
    public const int MaximumTitle = 160;
    public const int MaximumIndicator = 512;

    public static IEnumerable<SecurityFindingObservation> FromHardening(HardeningPostureSnapshot snapshot) =>
        snapshot.Checks
            .Where(check => check.State == PostureStates.Finding && SecurityFindingCatalog.Severities.Contains(check.Severity))
            .Select(check => Create(SecurityFindingCatalog.Hardening, check.Id, check.Severity, check.Technique,
                $"{check.Title}: {check.Detail}", check.Id));

    public static IEnumerable<SecurityFindingObservation> FromFirewall(FirewallSnapshot snapshot) =>
        snapshot.Findings
            .Where(finding => SecurityFindingCatalog.Severities.Contains(finding.Severity))
            .Select(finding => Create(SecurityFindingCatalog.Firewall, "Firewall", finding.Severity, finding.Technique, finding.Summary, finding.Indicator));

    public static IEnumerable<SecurityFindingObservation> FromPersistence(PersistenceSnapshot snapshot) =>
        snapshot.Findings
            .Where(finding => SecurityFindingCatalog.Severities.Contains(finding.Severity))
            // The summary of new/modified items includes a change verb; identity uses category + indicator so a later
            // re-scan of the same item updates the existing alert instead of creating a duplicate.
            .Select(finding => Create(SecurityFindingCatalog.Persistence, finding.Category, finding.Severity, finding.Technique, finding.Summary, finding.Indicator));

    public static IEnumerable<SecurityFindingObservation> FromUsb(UsbSnapshot snapshot) =>
        snapshot.Findings
            .Where(finding => SecurityFindingCatalog.Severities.Contains(finding.Severity))
            .Select(finding => Create(SecurityFindingCatalog.Usb, "USB", finding.Severity, finding.Technique, finding.Summary, finding.Indicator));

    public static IEnumerable<SecurityFindingObservation> FromWireless(WirelessSnapshot snapshot) =>
        snapshot.Findings
            .Where(finding => SecurityFindingCatalog.Severities.Contains(finding.Severity))
            .Select(finding => Create(SecurityFindingCatalog.Wireless, "Wireless", finding.Severity, finding.Technique, finding.Summary, finding.Indicator));

    public static IEnumerable<SecurityFindingObservation> FromRemoteAccess(RemoteAccessSnapshot snapshot) =>
        snapshot.Findings
            .Where(finding => SecurityFindingCatalog.Severities.Contains(finding.Severity))
            .Select(finding => Create(SecurityFindingCatalog.RemoteAccess, "Remote access", finding.Severity, finding.Technique, finding.Summary, finding.Indicator));

    public static SecurityFindingObservation Create(string source, string category, string severity, string technique, string summary, string indicator) =>
        new(source, Bound(category, 128), severity, string.IsNullOrWhiteSpace(technique) ? "Posture" : Bound(technique, 32),
            Bound(Clean(summary), MaximumTitle), Bound(indicator, MaximumIndicator));

    /// <summary>Stable 32-hex identity stored in the Provider column; scoped by source, category and indicator.</summary>
    public static string Identity(SecurityFindingObservation finding) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"downpour-finding-v1\0{finding.Source}\0{finding.Category}\0{finding.Indicator}")))[..32].ToLowerInvariant();

    private static string Clean(string value) => new(value.Select(ch => char.IsControl(ch) ? ' ' : ch).ToArray());

    private static string Bound(string value, int max) => value.Length <= max ? value : value[..(max - 1)] + "…";
}
