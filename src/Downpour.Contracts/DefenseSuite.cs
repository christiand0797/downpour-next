namespace Downpour.Contracts;

/// <summary>
/// Status and health of a core defense pillar within the unified defense suite.
/// </summary>
public sealed record DefensePillarStatus(
    string PillarId,
    string Title,
    string Status,
    string Summary,
    int Score,
    string RouteId);

/// <summary>
/// Finding produced by an advanced defense watcher inspecting an attack surface vector.
/// </summary>
public sealed record DefenseWatcherFinding(
    string WatcherId,
    string Category,
    string Severity,
    string Title,
    string Description,
    string MitreTechnique,
    string ObservedState,
    bool IsFlagged);

/// <summary>
/// Point-in-time snapshot of the overall defense posture, attack surface exposure, and active watchers.
/// </summary>
public sealed record DefenseSuiteSnapshot(
    DateTimeOffset CapturedAtUtc,
    int OverallDefenseScore,
    int AttackSurfaceExposure,
    IReadOnlyList<DefensePillarStatus> Pillars,
    IReadOnlyList<DefenseWatcherFinding> WatcherFindings,
    int HighRiskFindingsCount,
    int CleanFindingsCount);
