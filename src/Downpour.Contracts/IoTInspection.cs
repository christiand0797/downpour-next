namespace Downpour.Contracts;

/// <summary>
/// Information regarding a discovered network device on the local subnet.
/// </summary>
public sealed record IoTDevice(
    string IpAddress,
    string MacAddress,
    string HostName,
    string Vendor,
    string DeviceCategory,
    IReadOnlyList<int> OpenPorts,
    IReadOnlyList<string> IdentifiedServices,
    IReadOnlyList<string> BotnetIndicators,
    string ThreatLevel,
    int RiskScore,
    bool IsSuspicious,
    DateTimeOffset DiscoveredAtUtc);

/// <summary>
/// Aggregate summary of local subnet IoT security posture.
/// </summary>
public sealed record IoTSummary(
    int TotalDevices,
    int HighRiskDevices,
    int BotnetThreats,
    int SmartHomeDevices,
    int Cameras,
    DateTimeOffset ScanCompletedAtUtc,
    IReadOnlyList<string> ScanFindings);

/// <summary>
/// Complete snapshot of IoT network discovery and threat indicators.
/// </summary>
public sealed record IoTSnapshot(
    DateTimeOffset CapturedAtUtc,
    IoTSummary Summary,
    IReadOnlyList<IoTDevice> Devices);
