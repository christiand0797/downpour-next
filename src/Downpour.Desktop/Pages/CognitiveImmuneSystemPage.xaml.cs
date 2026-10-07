using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;

namespace Downpour_Desktop.Pages;

public sealed partial class CognitiveImmuneSystemPage : Page
{
    private readonly CognitiveImmuneSystemCoordinator _coordinator = new();
    private readonly ObservableCollection<HoneypotItemViewModel> _honeypotItems = new();
    private readonly ObservableCollection<HoneytokenItemViewModel> _honeytokenItems = new();
    private CisSnapshot? _currentSnapshot;
    private SwarmPredictionReport? _latestSwarmReport;

    public CognitiveImmuneSystemPage()
    {
        InitializeComponent();
        HoneypotListView.ItemsSource = _honeypotItems;
        HoneytokenListView.ItemsSource = _honeytokenItems;

        Loaded += (_, _) => RefreshUi();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshUi();
        NotificationInfoBar.IsOpen = true;
        NotificationInfoBar.Severity = InfoBarSeverity.Success;
        NotificationInfoBar.Title = "Telemetry Updated";
        NotificationInfoBar.Message = "Cognitive Immune System detector pools and subsystem telemetry refreshed.";
    }

    private async void RedTeamProbeButton_Click(object sender, RoutedEventArgs e)
    {
        RedTeamProbeButton.IsEnabled = false;
        try
        {
            var result = await Task.Run(() => _coordinator.ExecuteAdversarialProbe(30));
            RefreshUi();

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Adversarial Probe Completed";
            NotificationInfoBar.Message = $"Simulated 30 evasion vectors. Immune resistance: {result.EvasionResistanceScore}%. Intercepted detections: {result.DetectionsCount}.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Probe Failed";
            NotificationInfoBar.Message = ex.Message;
        }
        finally
        {
            RedTeamProbeButton.IsEnabled = true;
        }
    }

    private void ToggleRedTeamerButton_Click(object sender, RoutedEventArgs e)
    {
        bool isRunning = _coordinator.ToggleRedTeamer();
        RefreshUi();

        NotificationInfoBar.IsOpen = true;
        NotificationInfoBar.Severity = InfoBarSeverity.Informational;
        NotificationInfoBar.Title = "Adversarial Red Teamer";
        NotificationInfoBar.Message = isRunning
            ? "Adversarial Red Teamer started. Continuous synthetic evasion generation active."
            : "Adversarial Red Teamer stopped.";
    }

    private void TogglePredictorButton_Click(object sender, RoutedEventArgs e)
    {
        bool isRunning = _coordinator.TogglePredictor();
        RefreshUi();

        NotificationInfoBar.IsOpen = true;
        NotificationInfoBar.Severity = InfoBarSeverity.Informational;
        NotificationInfoBar.Title = "Threat Evolution Predictor";
        NotificationInfoBar.Message = isRunning
            ? "Threat Evolution Predictor active. Anticipating mutation trajectories across 48h horizon."
            : "Threat Evolution Predictor paused.";
    }

    private void ToggleVerifierButton_Click(object sender, RoutedEventArgs e)
    {
        bool isMonitoring = _coordinator.ToggleVerifier();
        RefreshUi();

        NotificationInfoBar.IsOpen = true;
        NotificationInfoBar.Severity = InfoBarSeverity.Informational;
        NotificationInfoBar.Title = "Semantic Integrity Verifier";
        NotificationInfoBar.Message = isMonitoring
            ? "Semantic Integrity Verifier active. Monitoring process and memory hash baselines."
            : "Semantic Integrity Verifier paused.";
    }

    private void ExportReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_currentSnapshot is null)
        {
            RefreshUi();
        }

        if (_currentSnapshot is null) return;

        try
        {
            string markdown = _coordinator.GenerateCisAuditReport(_currentSnapshot);
            var package = new DataPackage();
            package.SetText(markdown);
            Clipboard.SetContent(package);

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Report Exported";
            NotificationInfoBar.Message = "Cognitive Immune System intelligence report copied to clipboard in Markdown format.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Export Failed";
            NotificationInfoBar.Message = ex.Message;
        }
    }

    private async void SwarmSimButton_Click(object sender, RoutedEventArgs e)
    {
        SwarmSimButton.IsEnabled = false;
        RunSwarmButton.IsEnabled = false;
        try
        {
            var report = await Task.Run(() => _coordinator.RunSwarmSimulation(3));
            _latestSwarmReport = report;
            RefreshUi();

            SwarmStatusBadgeText.Text = $"SIMULATED ({report.RoundsSimulated} ROUNDS)";
            SwarmConsensusText.Text = $"{report.ThreatConsensusRatio:P0}";
            SwarmResistanceText.Text = $"{report.EvasionResistanceScore}%";
            SwarmDriftVectorsText.Text = $"{report.Projected48hDriftVectors} (48h)";
            SwarmLastRunText.Text = report.GeneratedAtUtc.ToString("HH:mm:ss UTC");
            SwarmExecutiveSnippetText.Text = string.Join(" • ", report.EmergentVulnerabilities);
            CopySwarmReportButton.IsEnabled = true;

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Swarm Intelligence Simulation Complete";
            NotificationInfoBar.Message = $"MiroFish OASIS engine completed {report.RoundsSimulated} rounds across {report.ActiveAgentsCount} agents. Equilibrium consensus: {report.ThreatConsensusRatio:P0}.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Swarm Simulation Failed";
            NotificationInfoBar.Message = ex.Message;
        }
        finally
        {
            SwarmSimButton.IsEnabled = true;
            RunSwarmButton.IsEnabled = true;
        }
    }

    private void CopySwarmReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_latestSwarmReport is null) return;

        try
        {
            var package = new DataPackage();
            package.SetText(_latestSwarmReport.ExecutiveSummary);
            Clipboard.SetContent(package);

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Swarm Report Copied";
            NotificationInfoBar.Message = "MiroFish prediction and emergent threat forecast report copied to clipboard.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Copy Failed";
            NotificationInfoBar.Message = ex.Message;
        }
    }

    private void RefreshUi()
    {
        var snapshot = _coordinator.GetSnapshot();
        _currentSnapshot = snapshot;

        // Every metric on this page is generated by an in-memory model, not measured on this PC (see the banner).
        StatusBadgeText.Text = "CONCEPT DEMO";

        MetricTotalDetectors.Text = snapshot.DetectorStats.TotalDetectors.ToString("N0");
        MetricMemoryEpitopes.Text = snapshot.DetectorStats.MemoryEpitopes.ToString("N0");
        MetricResistanceScore.Text = $"{snapshot.RedTeamer.EvasionResistanceScore}%";
        MetricPredictiveHorizon.Text = $"{snapshot.Predictor.HorizonHours}h ({snapshot.Predictor.PredictiveConfidence}%)";

        // Red Teamer
        bool rtRunning = snapshot.RedTeamer.IsRunning;
        RedTeamerBadgeText.Text = rtRunning ? "RUNNING" : "STOPPED";
        RedTeamerBadge.Background = rtRunning
            ? new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59))
            : new SolidColorBrush(ColorHelper.FromArgb(255, 55, 65, 81));
        RedTeamerBadgeText.Foreground = rtRunning
            ? new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153))
            : new SolidColorBrush(ColorHelper.FromArgb(255, 229, 231, 235));
        ToggleRedTeamerButtonText.Text = rtRunning ? "Stop Red Teamer" : "Start Red Teamer";
        RtProbeRoundsText.Text = snapshot.RedTeamer.ProbeRounds.ToString();
        RtDetectionsText.Text = snapshot.RedTeamer.DetectionsCount.ToString();
        RtLastRunText.Text = snapshot.RedTeamer.LastRunUtc.HasValue
            ? snapshot.RedTeamer.LastRunUtc.Value.ToString("HH:mm:ss UTC")
            : "Never";

        // Predictor
        bool pRunning = snapshot.Predictor.IsRunning;
        PredictorBadgeText.Text = pRunning ? "ACTIVE" : "STOPPED";
        PredictorBadge.Background = pRunning
            ? new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59))
            : new SolidColorBrush(ColorHelper.FromArgb(255, 55, 65, 81));
        PredictorBadgeText.Foreground = pRunning
            ? new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153))
            : new SolidColorBrush(ColorHelper.FromArgb(255, 229, 231, 235));
        TogglePredictorButtonText.Text = pRunning ? "Stop Predictor" : "Start Predictor";
        TeDriftVectorsText.Text = snapshot.Predictor.ThreatDriftVectorsCount.ToString();
        TeMutationsText.Text = snapshot.Predictor.SimulatedMutationsCount.ToString();
        TeConfidenceText.Text = $"{snapshot.Predictor.PredictiveConfidence}%";

        // Verifier
        bool vMonitoring = snapshot.Verifier.IsMonitoring;
        VerifierBadgeText.Text = vMonitoring ? "MONITORING" : "STOPPED";
        VerifierBadge.Background = vMonitoring
            ? new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59))
            : new SolidColorBrush(ColorHelper.FromArgb(255, 55, 65, 81));
        VerifierBadgeText.Foreground = vMonitoring
            ? new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153))
            : new SolidColorBrush(ColorHelper.FromArgb(255, 229, 231, 235));
        ToggleVerifierButtonText.Text = vMonitoring ? "Stop Verifier" : "Start Verifier";
        SiHashesText.Text = snapshot.Verifier.VerifiedHashesCount.ToString();
        SiViolationsText.Text = snapshot.Verifier.IntegrityViolations.ToString();
        SiStatusText.Text = snapshot.Verifier.IntegrityViolations == 0 ? "Clean" : "Flagged";

        // Detector Pool Stats
        StatClonalExpansions.Text = snapshot.DetectorStats.ClonalExpansions.ToString();
        StatSomaticMutations.Text = snapshot.DetectorStats.SomaticMutations.ToString();
        StatDetectorsCreated.Text = snapshot.DetectorStats.DetectorsCreated.ToString();
        StatDetectorsRetired.Text = snapshot.DetectorStats.DetectorsRetired.ToString();
        StatActiveResponses.Text = snapshot.DetectorStats.ActiveResponses.ToString();
        StatSignalQueue.Text = snapshot.DetectorStats.SignalQueueSize.ToString();
        StatThreatsContained.Text = snapshot.DetectorStats.ThreatsContained.ToString();
        StatAutoimmuneEvents.Text = snapshot.DetectorStats.AutoimmuneEvents.ToString();

        // Honeypots
        _honeypotItems.Clear();
        foreach (var pot in snapshot.Honeypots)
        {
            _honeypotItems.Add(new HoneypotItemViewModel(pot));
        }

        // Honeytokens
        _honeytokenItems.Clear();
        foreach (var tok in snapshot.Honeytokens)
        {
            _honeytokenItems.Add(new HoneytokenItemViewModel(tok));
        }
    }
}

public sealed class HoneypotItemViewModel
{
    public string Name { get; }
    public string ProtocolPort { get; }
    public string Banner { get; }
    public string InteractionSummary { get; }

    public HoneypotItemViewModel(CisHoneypotInfo pot)
    {
        Name = pot.Name;
        ProtocolPort = $"{pot.Protocol} :{pot.Port}";
        Banner = pot.Banner;
        InteractionSummary = pot.InteractionCount == 0 ? "0 PROBES" : $"{pot.InteractionCount} PROBES";
    }
}

public sealed class HoneytokenItemViewModel
{
    public string Type { get; }
    public string Description { get; }
    public string Placement { get; }
    public string TriggerSummary { get; }

    public HoneytokenItemViewModel(CisHoneytokenInfo token)
    {
        Type = token.Type;
        Description = token.Description;
        Placement = $"Placement: {token.Placement}";
        TriggerSummary = token.TriggerCount == 0 ? "ARMED" : $"{token.TriggerCount} TRIPPED";
    }
}
