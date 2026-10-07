namespace Downpour.Contracts;

/// <summary>A posture or persistence finding to be tracked in the alert store alongside Windows event alerts.</summary>
public sealed record SecurityFindingObservation(string Source, string Category, string Severity, string Technique, string Summary, string Indicator);

/// <summary>
/// Finding alerts reuse the event alert columns: LogName is a <see cref="Sources"/> value, Provider is a 32-hex
/// identity hash of the finding, and EventId is 0. Because the false-positive fingerprint is derived from those
/// three columns, "mark false positive" applies to the individual finding rather than the whole source.
/// </summary>
public static class SecurityFindingCatalog
{
    public const string Hardening = "Downpour/Hardening";
    public const string Firewall = "Downpour/Firewall";
    public const string Persistence = "Downpour/Persistence";
    public const string Usb = "Downpour/Usb";
    public const string Wireless = "Downpour/Wireless";
    public const string Sigma = "Downpour/Sigma";
    public const string Amsi = "Downpour/Amsi";
    public const string RemoteAccess = "Downpour/RemoteAccess";
    public const string Dns = "Downpour/Dns";

    public static readonly IReadOnlySet<string> Sources = new HashSet<string>(StringComparer.Ordinal) { Hardening, Firewall, Persistence, Usb, Wireless, Sigma, Amsi, RemoteAccess, Dns };
    public static readonly IReadOnlySet<string> Severities = new HashSet<string>(StringComparer.Ordinal) { "CRITICAL", "HIGH", "MEDIUM", "LOW" };

    public static bool IsFinding(string logName) => Sources.Contains(logName);

    public static bool IsValidIdentity(string provider) =>
        provider is { Length: 32 } && provider.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>v29 routing: high-severity detections went to the Threat Log; the rest wait in Possible Threats until verified.</summary>
    public static bool IsThreat(SecurityAlert alert) => alert.IsVerified || alert.Severity is "CRITICAL" or "HIGH";
}
