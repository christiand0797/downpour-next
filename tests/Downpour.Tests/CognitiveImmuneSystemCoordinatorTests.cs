using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class CognitiveImmuneSystemCoordinatorTests
{
    [Fact]
    public void GetSnapshot_ReturnsValidBaselineImmuneSystemState()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();
        var snapshot = coordinator.GetSnapshot();

        Assert.NotNull(snapshot);
        Assert.NotEmpty(snapshot.Status);
        Assert.NotNull(snapshot.DetectorStats);
        Assert.True(snapshot.DetectorStats.TotalDetectors > 1000);
        Assert.True(snapshot.DetectorStats.MemoryEpitopes > 100);
        Assert.Equal(0, snapshot.DetectorStats.AutoimmuneEvents);

        Assert.NotNull(snapshot.RedTeamer);
        Assert.False(snapshot.RedTeamer.IsRunning);
        Assert.True(snapshot.RedTeamer.EvasionResistanceScore >= 90);

        Assert.NotNull(snapshot.Predictor);
        Assert.True(snapshot.Predictor.IsRunning);
        Assert.True(snapshot.Predictor.PredictiveConfidence > 80);

        Assert.NotNull(snapshot.Verifier);
        Assert.True(snapshot.Verifier.IsMonitoring);
        Assert.Equal(0, snapshot.Verifier.IntegrityViolations);

        Assert.Equal(6, snapshot.Honeypots.Count);
        Assert.Equal(6, snapshot.Honeytokens.Count);
        Assert.Empty(snapshot.DeceptionEvents);
    }

    [Fact]
    public void ToggleRedTeamer_FlipsRunningState()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();

        bool running1 = coordinator.ToggleRedTeamer();
        Assert.True(running1);

        var snap1 = coordinator.GetSnapshot();
        Assert.True(snap1.RedTeamer.IsRunning);
        Assert.NotNull(snap1.RedTeamer.LastRunUtc);

        bool running2 = coordinator.ToggleRedTeamer();
        Assert.False(running2);

        var snap2 = coordinator.GetSnapshot();
        Assert.False(snap2.RedTeamer.IsRunning);
    }

    [Fact]
    public void ExecuteAdversarialProbe_IncrementsRoundsAndDetections()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();

        var state1 = coordinator.ExecuteAdversarialProbe(simulatedPerturbations: 30);
        Assert.Equal(1, state1.ProbeRounds);
        Assert.True(state1.DetectionsCount > 0);
        Assert.NotNull(state1.LastRunUtc);
        Assert.InRange(state1.EvasionResistanceScore, 90, 100);

        var state2 = coordinator.ExecuteAdversarialProbe(simulatedPerturbations: 20);
        Assert.Equal(2, state2.ProbeRounds);
        Assert.True(state2.DetectionsCount > state1.DetectionsCount);
    }

    [Fact]
    public void TogglePredictorAndVerifier_ControlsSubsystemLifecycle()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();

        // Predictor defaults to running
        Assert.True(coordinator.GetSnapshot().Predictor.IsRunning);
        bool pState = coordinator.TogglePredictor();
        Assert.False(pState);
        Assert.False(coordinator.GetSnapshot().Predictor.IsRunning);

        // Verifier defaults to monitoring
        Assert.True(coordinator.GetSnapshot().Verifier.IsMonitoring);
        bool vState = coordinator.ToggleVerifier();
        Assert.False(vState);
        Assert.False(coordinator.GetSnapshot().Verifier.IsMonitoring);
    }

    [Fact]
    public void RecordDeceptionInteraction_UpdatesHoneypotsAndEventLog()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();

        coordinator.RecordDeceptionInteraction(
            sourceEndpoint: "192.168.1.185:54321",
            targetDecoy: "ssh_honeypot",
            decoyType: "Honeypot",
            severity: "High",
            details: "Simulated brute-force login probe with credentials admin:admin");

        var snapshot = coordinator.GetSnapshot();
        Assert.Single(snapshot.DeceptionEvents);
        Assert.Equal("192.168.1.185:54321", snapshot.DeceptionEvents[0].SourceEndpoint);
        Assert.Equal("ssh_honeypot", snapshot.DeceptionEvents[0].TargetDecoy);

        var pot = snapshot.Honeypots.First(p => p.Name == "ssh_honeypot");
        Assert.Equal(1, pot.InteractionCount);
    }

    [Fact]
    public void RecordDeceptionInteraction_UpdatesHoneytokenTriggers()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();

        coordinator.RecordDeceptionInteraction(
            sourceEndpoint: "Host:DESKTOP-1",
            targetDecoy: "fake_aws_creds",
            decoyType: "Honeytoken",
            severity: "Critical",
            details: "Canary token accessed from staging directory");

        var snapshot = coordinator.GetSnapshot();
        Assert.Single(snapshot.DeceptionEvents);

        var tok = snapshot.Honeytokens.First(t => t.TokenId == "fake_aws_creds");
        Assert.Equal(1, tok.TriggerCount);
    }

    [Fact]
    public void GenerateCisAuditReport_ProducesCompleteExecutiveMarkdown()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();
        coordinator.ExecuteAdversarialProbe();
        coordinator.RecordDeceptionInteraction("10.0.0.99", "http_honeypot", "Honeypot", "Medium", "GET /admin probe");

        var snapshot = coordinator.GetSnapshot();
        string report = coordinator.GenerateCisAuditReport(snapshot);

        Assert.Contains("# Cognitive Immune System (CIS) Posture & Intelligence Report", report);
        Assert.Contains("Total Detectors", report);
        Assert.Contains("Memory Epitopes", report);
        Assert.Contains("Clonal Expansions", report);
        Assert.Contains("Adversarial Red Teamer", report);
        Assert.Contains("Threat Evolution Predictor", report);
        Assert.Contains("Semantic Integrity Verifier", report);
        Assert.Contains("Deception Technology & Honeypots", report);
        Assert.Contains("Deployed Honeytokens (Canary Tripwires)", report);
        Assert.Contains("ssh_honeypot", report);
        Assert.Contains("fake_aws_creds", report);
    }

    [Fact]
    public void RunSwarmSimulation_UpdatesCoordinatorMetricsAndProducesReport()
    {
        var coordinator = new CognitiveImmuneSystemCoordinator();
        var report = coordinator.RunSwarmSimulation(rounds: 3);

        Assert.NotNull(report);
        Assert.StartsWith("SWARM-", report.SimulationId);
        Assert.Equal(3, report.RoundsSimulated);
        Assert.Equal(8, report.ActiveAgentsCount);
        Assert.InRange(report.ThreatConsensusRatio, 0.1, 1.0);
        Assert.InRange(report.EvasionResistanceScore, 80, 100);
        Assert.NotEmpty(report.EmergentVulnerabilities);
        Assert.NotEmpty(report.RemediationRecommendations);
        Assert.Contains("MiroFish Swarm Intelligence Prediction Report", report.ExecutiveSummary);
        Assert.Equal(8, report.Agents.Count);
        Assert.True(report.KeyInteractions.Count > 0);

        var snapshot = coordinator.GetSnapshot();
        Assert.Equal(report.Projected48hDriftVectors, snapshot.Predictor.ThreatDriftVectorsCount);
        Assert.Equal(report.EvasionResistanceScore, snapshot.RedTeamer.EvasionResistanceScore);
    }
}
