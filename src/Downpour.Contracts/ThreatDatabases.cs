namespace Downpour.Contracts;

/// <summary>What one allow-listed public threat database contains.</summary>
public static class ThreatFeedKinds
{
    public const string Ip = "ip";
    public const string Domain = "domain";
    public const string Hash = "hash";
    public const string Driver = "driver";
    public const string Lolbin = "lolbin";
    public const string Mixed = "mixed";
    public const string Geo = "geo";
}

/// <summary>Local state of one feed. Nothing about this PC is sent to the source; feeds are downloaded whole.</summary>
public sealed record ThreatFeedStatus(
    string Id,
    string Name,
    string Provider,
    string Kind,
    string Purpose,
    string License,
    string Homepage,
    string State,
    int Entries,
    DateTimeOffset? RetrievedAtUtc,
    DateTimeOffset? NextRefreshUtc,
    long Bytes,
    string? Error);

public static class ThreatFeedStates
{
    public const string Current = "current";
    public const string Stale = "stale";
    public const string Updating = "updating";
    public const string Failed = "failed";
    public const string NotLoaded = "not-loaded";
    public const string Disabled = "disabled";
}

/// <summary>One local observation (connection, DNS name, loaded driver, running program) that a threat database lists.</summary>
public sealed record ThreatMatch(
    DateTimeOffset SeenAtUtc,
    string Where,
    string Indicator,
    string Subject,
    string FeedId,
    string FeedName,
    string Label,
    string Severity,
    string Technique,
    string Verdict = "needs-review",
    int Confidence = 0,
    IReadOnlyList<string>? Reasons = null);

public static class ThreatMatchPlaces
{
    public const string Connection = "Network connection";
    public const string Dns = "DNS lookup";
    public const string Driver = "Loaded driver";
    public const string Program = "Running program";
}

/// <summary>A running living-off-the-land binary, shown as context (these are normal Windows tools that attackers also abuse).</summary>
public sealed record LolbinObservation(string Name, string Categories, string Techniques, int Instances);

public sealed record ThreatDatabaseCoverage(
    int ConnectionsChecked,
    int DomainsChecked,
    int DriversHashed,
    int ProgramsHashed,
    DateTimeOffset? LastSweepUtc,
    TimeSpan? LastSweepDuration);

public sealed record ThreatDatabaseSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    bool UpdatesEnabled,
    int TotalIndicators,
    IReadOnlyList<ThreatFeedStatus> Feeds,
    IReadOnlyList<ThreatMatch> Matches,
    IReadOnlyList<LolbinObservation> Lolbins,
    ThreatDatabaseCoverage Coverage,
    IReadOnlyList<RemoteConnectionOrigin> Connections,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Approximate origin of a public IP from an offline database: the country the address block is registered in and the
/// network (ISP, hosting company or VPN) that announces it. It locates a network, never a person or street address.
/// </summary>
public sealed record IpOrigin(string Ip, string? CountryCode, int? Asn, string? Network);

/// <summary>An established connection from a program on this PC to a public address, with its approximate origin.</summary>
public sealed record RemoteConnectionOrigin(
    string Program,
    int ProcessId,
    string RemoteAddress,
    int RemotePort,
    string? CountryCode,
    int? Asn,
    string? Network,
    bool Listed);

/// <summary>
/// Operation = "snapshot", "refresh" (download due/failed feeds now), "lookup" (check one IP, domain, URL or hash locally),
/// or "browse" (list entries of <see cref="FeedId"/>, optionally filtered by the text in Value).
/// </summary>
public sealed record ThreatDatabaseRequest(int SchemaVersion, string Operation, string? Value, string? FeedId = null);

/// <summary>One entry of a downloaded database, for browsing.</summary>
public sealed record ThreatBrowseRow(string Value, string Type, string Label);

public sealed record ThreatLookupHit(string FeedId, string FeedName, string Label);

public sealed record ThreatDatabaseResponse(
    int SchemaVersion,
    bool Accepted,
    string ResultCode,
    ThreatDatabaseSnapshot? Snapshot,
    string? LookupKind,
    string? LookupValue,
    IReadOnlyList<ThreatLookupHit>? LookupHits,
    IpOrigin? LookupOrigin = null,
    IReadOnlyList<ThreatBrowseRow>? Browse = null,
    int BrowseTotal = 0);

public static class ThreatDatabaseOperations
{
    public const string Snapshot = "snapshot";
    public const string Refresh = "refresh";
    public const string Lookup = "lookup";
    public const string Browse = "browse";
}
