using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class DefenseSuiteCoordinatorTests
{
    [Fact]
    public void EvaluateDefensePosture_WithAllCleanFindings_ProducesPerfectScore()
    {
        var coordinator = new DefenseSuiteCoordinator();

        var cleanFindings = new List<DefenseWatcherFinding>
        {
            new("IFEO_HIJACK", "Persistence", "Clean", "IFEO Process Execution Hijack", "Clean", "T1546.012", "Clean", false),
            new("LSA_PPL", "Defense Evasion", "Clean", "LSA Protection (RunAsPPL)", "Clean", "T1003", "Clean", false),
            new("UAC_POLICY", "Privilege Escalation", "Clean", "UAC Elevation Enforcement", "Clean", "T1548.002", "Clean", false),
            new("CERT_STORE", "Credential Access", "Clean", "Trusted Root CA Store Monitor", "Clean", "T1553.004", "Clean", false)
        };

        var snapshot = coordinator.EvaluateDefensePosture(cleanFindings);

        Assert.Equal(100, snapshot.OverallDefenseScore);
        Assert.Equal(0, snapshot.AttackSurfaceExposure);
        Assert.Equal(0, snapshot.HighRiskFindingsCount);
        Assert.Equal(4, snapshot.CleanFindingsCount);
        Assert.Equal(4, snapshot.Pillars.Count);
        Assert.Contains(snapshot.Pillars, p => p.PillarId == "aegis" && p.RouteId == "aegis");
        Assert.Contains(snapshot.Pillars, p => p.PillarId == "ransomware" && p.RouteId == "ransomware");
        Assert.Contains(snapshot.Pillars, p => p.PillarId == "hardening" && p.RouteId == "hardening");
        Assert.Contains(snapshot.Pillars, p => p.PillarId == "emergency" && p.RouteId == "emergency");
    }

    [Fact]
    public void EvaluateDefensePosture_WithFlaggedFindings_CalculatesAccuratePenalties()
    {
        var coordinator = new DefenseSuiteCoordinator();

        var mixedFindings = new List<DefenseWatcherFinding>
        {
            new("IFEO_HIJACK", "Persistence", "Critical", "IFEO Hijack", "Hijack present", "T1546.012", "Flagged", true), // -25
            new("UAC_POLICY", "Privilege Escalation", "High", "UAC Silent", "Silent elevation", "T1548.002", "Flagged", true), // -15
            new("LSA_PPL", "Defense Evasion", "Medium", "LSA Disabled", "LSA not PPL", "T1003", "Flagged", true), // -8
            new("SMB_SHARES", "Lateral Movement", "Low", "SMB Shares", "Open shares", "T1021.002", "Flagged", true), // -3
            new("CERT_STORE", "Credential Access", "Clean", "Cert Store", "Valid certs", "T1553.004", "Clean", false)
        };

        // Expected deductions: 25 + 15 + 8 + 3 = 51. Defense score: 100 - 51 = 49. Attack surface: 51.
        var snapshot = coordinator.EvaluateDefensePosture(mixedFindings);

        Assert.Equal(49, snapshot.OverallDefenseScore);
        Assert.Equal(51, snapshot.AttackSurfaceExposure);
        Assert.Equal(2, snapshot.HighRiskFindingsCount); // 1 Critical + 1 High
        Assert.Equal(1, snapshot.CleanFindingsCount);
    }

    [Fact]
    public void EvaluateDefensePosture_WithExcessiveVulnerabilities_ClampsToZero()
    {
        var coordinator = new DefenseSuiteCoordinator();

        var severeFindings = new List<DefenseWatcherFinding>
        {
            new("F1", "Test", "Critical", "Crit 1", "desc", "T1", "state", true),
            new("F2", "Test", "Critical", "Crit 2", "desc", "T2", "state", true),
            new("F3", "Test", "Critical", "Crit 3", "desc", "T3", "state", true),
            new("F4", "Test", "Critical", "Crit 4", "desc", "T4", "state", true),
            new("F5", "Test", "Critical", "Crit 5", "desc", "T5", "state", true) // 5 * 25 = 125 deductions
        };

        var snapshot = coordinator.EvaluateDefensePosture(severeFindings);

        Assert.Equal(0, snapshot.OverallDefenseScore);
        Assert.Equal(100, snapshot.AttackSurfaceExposure);
    }

    [Fact]
    public void RunAllWatchers_ExecutesWithoutExceptionsAndReturnsWatchers()
    {
        var findings = DefenseSuiteCoordinator.RunAllWatchers();

        Assert.NotNull(findings);
        Assert.NotEmpty(findings);
        Assert.True(findings.Count >= 8);

        foreach (var finding in findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.WatcherId));
            Assert.False(string.IsNullOrWhiteSpace(finding.Category));
            Assert.False(string.IsNullOrWhiteSpace(finding.Severity));
            Assert.False(string.IsNullOrWhiteSpace(finding.Title));
            Assert.False(string.IsNullOrWhiteSpace(finding.MitreTechnique));
            Assert.False(string.IsNullOrWhiteSpace(finding.ObservedState));
        }
    }

    [Fact]
    public void InspectMemoryExploitationGuard_ReturnsCleanMitigationFinding()
    {
        var finding = DefenseSuiteCoordinator.InspectMemoryExploitationGuard();

        Assert.NotNull(finding);
        Assert.Equal("DEP_ASLR", finding.WatcherId);
        Assert.Equal("Execution", finding.Category);
        Assert.Equal("T1055", finding.MitreTechnique);
        Assert.False(finding.IsFlagged);
    }

    [Fact]
    public void GenerateDefensePostureReport_IncludesExecutiveSectionsAndRemediations()
    {
        var coordinator = new DefenseSuiteCoordinator();

        var findings = new List<DefenseWatcherFinding>
        {
            new("IFEO_HIJACK", "Persistence", "Critical", "IFEO Process Execution Hijack", "Sticky keys hijacked.", "T1546.012", "sethc.exe -> cmd.exe", true),
            new("LSA_PPL", "Defense Evasion", "Clean", "LSA Protection (RunAsPPL)", "Clean.", "T1003", "RunAsPPL=1", false)
        };

        var snapshot = coordinator.EvaluateDefensePosture(findings);
        string report = coordinator.GenerateDefensePostureReport(snapshot);

        Assert.Contains("# Advanced Defense Suite Executive Posture Report", report);
        Assert.Contains("Overall Defense Posture Score", report);
        Assert.Contains("Attack Surface Exposure", report);
        Assert.Contains("Core Defense Pillars Status", report);
        Assert.Contains("Project AEGIS", report);
        Assert.Contains("Ransomware Defense", report);
        Assert.Contains("Hardening & Firmware", report);
        Assert.Contains("Emergency Response", report);
        Assert.Contains("Advanced Attack Surface Watchers", report);
        Assert.Contains("Recommended Remediation & Hardening", report);
        Assert.Contains("IFEO Process Execution Hijack", report);
        Assert.Contains("sethc.exe -> cmd.exe", report);
    }

    [Fact]
    public void GenerateDefensePostureReport_WhenAllClean_NotesCleanBaseline()
    {
        var coordinator = new DefenseSuiteCoordinator();
        var cleanFindings = new List<DefenseWatcherFinding>
        {
            new("DEP_ASLR", "Execution", "Clean", "System DEP & ASLR Mitigation", "Clean", "T1055", "Active", false)
        };

        var snapshot = coordinator.EvaluateDefensePosture(cleanFindings);
        string report = coordinator.GenerateDefensePostureReport(snapshot);

        Assert.Contains("All defense watchers report optimal baseline security", report);
    }
}
