namespace Downpour.Contracts;

/// <summary>
/// Clonal selection and artificial immune detector pool statistics.
/// </summary>
public sealed record CisDetectorStats(
    int TotalDetectors,
    int MemoryEpitopes,
    int ActiveResponses,
    int SignalQueueSize,
    int ClonalExpansions,
    int SomaticMutations,
    int DetectorsCreated,
    int DetectorsRetired,
    int ThreatsContained,
    int AutoimmuneEvents);

/// <summary>
/// Status and execution telemetry of the Adversarial Red Teamer subsystem.
/// </summary>
public sealed record CisRedTeamerState(
    bool IsRunning,
    DateTimeOffset? LastRunUtc,
    int DetectionsCount,
    int ProbeRounds,
    int EvasionResistanceScore);

/// <summary>
/// Status and horizon metrics of the Threat Evolution Predictor subsystem.
/// </summary>
public sealed record CisPredictorState(
    bool IsRunning,
    int ThreatDriftVectorsCount,
    int SimulatedMutationsCount,
    int HorizonHours,
    int PredictiveConfidence);

/// <summary>
/// Status and verification telemetry of the Semantic Integrity Verifier subsystem.
/// </summary>
public sealed record CisVerifierState(
    bool IsMonitoring,
    int VerifiedHashesCount,
    int IntegrityViolations,
    string StatusSummary);

/// <summary>
/// Configuration and telemetry for an active decoy honeypot service.
/// </summary>
public sealed record CisHoneypotInfo(
    string Name,
    string Protocol,
    int Port,
    bool IsEnabled,
    int InteractionCount,
    string Banner);

/// <summary>
/// Configuration and telemetry for a deployed canary honeytoken.
/// </summary>
public sealed record CisHoneytokenInfo(
    string TokenId,
    string Type,
    string Description,
    string Placement,
    int TriggerCount,
    bool IsAlertOnAccess);

/// <summary>
/// Audit entry recording a honeypot interaction or honeytoken tripwire breach.
/// </summary>
public sealed record CisDeceptionEvent(
    DateTimeOffset TimestampUtc,
    string SourceEndpoint,
    string TargetDecoy,
    string DecoyType,
    string Severity,
    string Details);

/// <summary>
/// Point-in-time snapshot of the Cognitive Immune System (CIS) posture, detectors, and deception state.
/// </summary>
public sealed record CisSnapshot(
    DateTimeOffset CapturedAtUtc,
    string Status,
    CisDetectorStats DetectorStats,
    CisRedTeamerState RedTeamer,
    CisPredictorState Predictor,
    CisVerifierState Verifier,
    IReadOnlyList<CisHoneypotInfo> Honeypots,
    IReadOnlyList<CisHoneytokenInfo> Honeytokens,
    IReadOnlyList<CisDeceptionEvent> DeceptionEvents);
