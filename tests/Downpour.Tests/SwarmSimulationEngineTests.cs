using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class SwarmSimulationEngineTests
{
    [Fact]
    public void InitializeDefaultSwarm_ContainsAllRequiredArchetypes()
    {
        var engine = new SwarmSimulationEngine();
        var report = engine.Simulate(1);

        Assert.Equal(8, report.Agents.Count);

        var archetypes = report.Agents.Select(a => a.Archetype).ToHashSet();
        Assert.Contains(SwarmAgentArchetype.Adversary, archetypes);
        Assert.Contains(SwarmAgentArchetype.Defender, archetypes);
        Assert.Contains(SwarmAgentArchetype.Forensics, archetypes);
        Assert.Contains(SwarmAgentArchetype.ImmuneSentinel, archetypes);
        Assert.Contains(SwarmAgentArchetype.DeceptionTrap, archetypes);
        Assert.Contains(SwarmAgentArchetype.Synthesizer, archetypes);

        foreach (var agent in report.Agents)
        {
            Assert.False(string.IsNullOrWhiteSpace(agent.AgentId));
            Assert.False(string.IsNullOrWhiteSpace(agent.Name));
            Assert.False(string.IsNullOrWhiteSpace(agent.Objective));
            Assert.False(string.IsNullOrWhiteSpace(agent.CurrentStrategy));
            Assert.InRange(agent.ConfidenceScore, 1, 100);
        }
    }

    [Fact]
    public void Simulate_SingleRound_GeneratesInteractionsAndUpdatesMetrics()
    {
        var engine = new SwarmSimulationEngine();
        var report = engine.Simulate(rounds: 1);

        Assert.Equal(1, report.RoundsSimulated);
        Assert.Equal(8, report.ActiveAgentsCount);
        Assert.NotEmpty(report.KeyInteractions);

        foreach (var interaction in report.KeyInteractions)
        {
            Assert.Equal(1, interaction.Round);
            Assert.False(string.IsNullOrWhiteSpace(interaction.SourceAgentId));
            Assert.False(string.IsNullOrWhiteSpace(interaction.TargetAgentId));
            Assert.False(string.IsNullOrWhiteSpace(interaction.ActionType));
            Assert.False(string.IsNullOrWhiteSpace(interaction.Outcome));
            Assert.False(string.IsNullOrWhiteSpace(interaction.Details));
        }

        // Agents should have incremented interaction counts
        Assert.All(report.Agents, a => Assert.True(a.InteractionCount > 0));
    }

    [Fact]
    public void Simulate_MultipleRounds_SynthesizesConsensusAndReport()
    {
        var engine = new SwarmSimulationEngine();
        var report = engine.Simulate(rounds: 4);

        Assert.Equal(4, report.RoundsSimulated);
        Assert.Equal(8, report.ActiveAgentsCount);
        Assert.InRange(report.ThreatConsensusRatio, 0.0, 1.0);
        Assert.InRange(report.EvasionResistanceScore, 80, 98);
        Assert.True(report.Projected48hDriftVectors > 0);

        Assert.NotEmpty(report.EmergentVulnerabilities);
        Assert.NotEmpty(report.RemediationRecommendations);

        Assert.Contains("MiroFish Swarm Intelligence Prediction Report", report.ExecutiveSummary);
        Assert.Contains("Emergent Threat Projections", report.ExecutiveSummary);
        Assert.Contains("Recommended Preemptive Countermeasures", report.ExecutiveSummary);
        Assert.Contains("Swarm Agent Roster", report.ExecutiveSummary);
    }

    [Theory]
    [InlineData(-5, 1)]
    [InlineData(0, 1)]
    [InlineData(15, 10)]
    public void Simulate_ClampsRoundsGracefully(int requestedRounds, int expectedRounds)
    {
        var engine = new SwarmSimulationEngine();
        var report = engine.Simulate(requestedRounds);

        Assert.Equal(expectedRounds, report.RoundsSimulated);
    }
}
