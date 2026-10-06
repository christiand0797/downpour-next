namespace Downpour.Contracts;

public sealed record FirewallProfileState(string Profile, bool IsActive, bool? Enabled, string DefaultInboundAction, string DefaultOutboundAction);

public sealed record FirewallRuleEntry(
    string Name,
    string Direction,
    string Action,
    bool Enabled,
    string Protocol,
    string LocalPorts,
    string RemoteAddresses,
    string Profiles,
    string Application,
    string Service,
    string AppPackage,
    string Grouping,
    bool IsDownpourRule);

public sealed record FirewallBlockedConnection(
    DateTimeOffset TimeUtc,
    string Direction,
    string Application,
    string SourceAddress,
    string DestinationAddress,
    string DestinationPort,
    string Protocol);

public sealed record FirewallFinding(string Severity, string Technique, string Summary, string Indicator);

public sealed record FirewallSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string ServiceState,
    IReadOnlyList<FirewallProfileState> Profiles,
    int RuleCount,
    IReadOnlyList<FirewallRuleEntry> Rules,
    string BlockedEventsStatus,
    IReadOnlyList<FirewallBlockedConnection> BlockedConnections,
    IReadOnlyList<FirewallFinding> Findings,
    IReadOnlyList<string> Warnings);

public static class FirewallBlockedEventsStatuses
{
    public const string Available = "Available";
    public const string NoEvents = "No events";
    public const string AccessDenied = "Access denied";
    public const string Unavailable = "Unavailable";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Available, NoEvents, AccessDenied, Unavailable };
}
