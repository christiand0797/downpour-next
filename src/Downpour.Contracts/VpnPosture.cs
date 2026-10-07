namespace Downpour.Contracts;

/// <summary>
/// Information regarding a discovered network interface and its VPN posture.
/// </summary>
public sealed record VpnInterfaceInfo(
    string Id,
    string Name,
    string Description,
    string InterfaceType,
    string OperationalStatus,
    IReadOnlyList<string> IpAddresses,
    IReadOnlyList<string> DnsServers,
    string Gateway,
    bool IsVpn,
    string DetectedProvider);

/// <summary>
/// DNS leak assessment comparing tunnel DNS resolvers against physical adapter DNS configuration.
/// </summary>
public sealed record DnsLeakAssessment(
    bool HasLeakRisk,
    string Status,
    IReadOnlyList<string> VpnDnsServers,
    IReadOnlyList<string> PhysicalDnsServers,
    IReadOnlyList<string> Findings);

/// <summary>
/// A known or imported VPN profile configuration.
/// </summary>
public sealed record VpnProfileSummary(
    string Name,
    string Protocol,
    string RemoteHost,
    int? RemotePort,
    string Source);

/// <summary>
/// Result of an outbound TCP connectivity probe on port 443.
/// </summary>
public sealed record ConnectivityTestResult(
    string Target,
    bool Reachable,
    int LatencyMs,
    string Details);

/// <summary>
/// Comprehensive snapshot of VPN network posture, adapters, DNS leak status, and profiles.
/// </summary>
public sealed record VpnPostureSnapshot(
    DateTimeOffset EvaluatedAtUtc,
    bool IsVpnConnected,
    string PrimaryProvider,
    IReadOnlyList<VpnInterfaceInfo> Interfaces,
    DnsLeakAssessment DnsLeak,
    IReadOnlyList<VpnProfileSummary> Profiles,
    IReadOnlyList<ConnectivityTestResult> ConnectivityTests,
    bool KillSwitchGuarded,
    IReadOnlyList<string> PostureFindings);
