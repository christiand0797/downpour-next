namespace Downpour.Contracts;

/// <summary>An indicator taken from a local alert. Only public addresses, hashes, and DNS-flagged domains qualify.</summary>
public sealed record IntelIndicator(string Kind, string Value);

public sealed record IntelLookupResult(
    string Service,
    string IndicatorKind,
    string Indicator,
    string Verdict,
    int? Score,
    string Summary,
    DateTimeOffset CheckedAtUtc);

/// <summary>One outbound lookup, recorded without the indicator value (SECURITY.md).</summary>
public sealed record IntelOutboundRecord(string Service, string IndicatorKind, DateTimeOffset SentAtUtc, string Outcome);

public sealed record IntelSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    bool Enabled,
    IReadOnlyList<string> ConfiguredServices,
    DateTimeOffset? LastRunUtc,
    string LastRunStatus,
    IReadOnlyList<IntelLookupResult> Results,
    IReadOnlyList<IntelOutboundRecord> RecentLookups,
    IReadOnlyList<string> Warnings);

public static class IntelServices
{
    public const string VirusTotal = "VirusTotal";
    public const string AbuseIpDb = "AbuseIPDB";
    public const string GreyNoise = "GreyNoise";
    public static readonly IReadOnlyList<string> All = [VirusTotal, AbuseIpDb, GreyNoise];
}

public static class IntelKinds
{
    public const string Ip = "ip";
    public const string Domain = "domain";
    public const string Hash = "hash";
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Ip, Domain, Hash };
}

public static class IntelVerdicts
{
    public const string Malicious = "Malicious";
    public const string Suspicious = "Suspicious";
    public const string Clean = "Clean";
    public const string Unknown = "Unknown";
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Malicious, Suspicious, Clean, Unknown };
}
