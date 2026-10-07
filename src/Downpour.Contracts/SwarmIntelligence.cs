namespace Downpour.Contracts;

/// <summary>
/// Archetype defining a swarm agent's behavioral strategy, goals, and role in threat simulation.
/// Inspired by the MiroFish multi-agent swarm intelligence paradigm.
/// </summary>
public enum SwarmAgentArchetype
{
    /// <summary>Adversary simulating evasive execution, LOLBins, and detection bypasses.</summary>
    Adversary,
    /// <summary>Defender evaluating Sigma, YARA, and heuristic rule interception.</summary>
    Defender,
    /// <summary>Forensic investigator correlating traces, timelines, and MITRE techniques.</summary>
    Forensics,
    /// <summary>Immune sentinel modeling clonal selection and epitope adaptation.</summary>
    ImmuneSentinel,
    /// <summary>Deception trap engaging honeytokens and decoys.</summary>
    DeceptionTrap,
    /// <summary>MiroFish-style ReportAgent synthesizing collective agent dynamics and consensus.</summary>
    Synthesizer
}

/// <summary>
/// Status and execution telemetry for an individual autonomous swarm agent.
/// </summary>
public sealed record SwarmAgentState(
    string AgentId,
    SwarmAgentArchetype Archetype,
    string Name,
    string Objective,
    string CurrentStrategy,
    int ConfidenceScore,
    int InteractionCount,
    int FindingsGenerated);

/// <summary>
/// Represents a discrete interaction between two swarm agents during a simulation round.
/// </summary>
public sealed record SwarmInteraction(
    int Round,
    string SourceAgentId,
    string TargetAgentId,
    string ActionType,
    string Outcome,
    string Details);

/// <summary>
/// Synthesized predictive threat intelligence report produced by the Swarm Synthesizer agent.
/// </summary>
public sealed record SwarmPredictionReport(
    string SimulationId,
    DateTimeOffset GeneratedAtUtc,
    int RoundsSimulated,
    int ActiveAgentsCount,
    double ThreatConsensusRatio,
    int EvasionResistanceScore,
    int Projected48hDriftVectors,
    IReadOnlyList<string> EmergentVulnerabilities,
    IReadOnlyList<string> RemediationRecommendations,
    string ExecutiveSummary,
    IReadOnlyList<SwarmAgentState> Agents,
    IReadOnlyList<SwarmInteraction> KeyInteractions);
