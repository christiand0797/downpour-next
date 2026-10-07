namespace Downpour.Contracts;

/// <summary>
/// Status and rapid launch metadata for an operational security tool.
/// </summary>
public sealed record OperationalToolCardInfo(
    string ToolId,
    string Title,
    string Category,
    string Status,
    string Summary,
    string TelemetryLabel,
    string TelemetryValue,
    string Glyph,
    string RouteId);

/// <summary>
/// Result of an operational system diagnostic check.
/// </summary>
public sealed record SystemDiagnosticCheck(
    string Name,
    string Category,
    string ObservedValue,
    bool IsPassed,
    string Details);

/// <summary>
/// Aggregated snapshot of all operational tools, diagnostics, and launchpads.
/// </summary>
public sealed record ToolsHubSnapshot(
    DateTimeOffset CapturedAtUtc,
    int TotalTools,
    string OperationalHealth,
    IReadOnlyList<OperationalToolCardInfo> Tools,
    IReadOnlyList<SystemDiagnosticCheck> Diagnostics);
