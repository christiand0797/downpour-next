using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;

namespace Downpour_Desktop.Pages;

public sealed partial class DefenseSuitePage : Page
{
    private readonly DefenseSuiteCoordinator _coordinator = new();
    private readonly ObservableCollection<WatcherItemViewModel> _watcherItems = new();
    private DefenseSuiteSnapshot? _currentSnapshot;

    public DefenseSuitePage()
    {
        InitializeComponent();
        WatcherListView.ItemsSource = _watcherItems;
        Loaded += async (_, _) => await EvaluatePostureAsync();
    }

    private async void EvaluateButton_Click(object sender, RoutedEventArgs e)
    {
        await EvaluatePostureAsync();
    }

    private async Task EvaluatePostureAsync()
    {
        EvaluateButton.IsEnabled = false;
        try
        {
            var snapshot = await Task.Run(() => _coordinator.EvaluateDefensePosture());
            _currentSnapshot = snapshot;

            MetricDefenseScore.Text = $"{snapshot.OverallDefenseScore}/100";
            MetricAttackSurface.Text = $"{snapshot.AttackSurfaceExposure}%";
            MetricActiveWatchers.Text = snapshot.WatcherFindings.Count.ToString();
            MetricFlaggedExposures.Text = snapshot.HighRiskFindingsCount.ToString();

            if (snapshot.OverallDefenseScore >= 90)
            {
                StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59));
                StatusBadge.BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 5, 150, 105));
                StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
                StatusBadgeText.Text = "OPTIMAL POSTURE";
                MetricDefenseScore.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
            }
            else if (snapshot.OverallDefenseScore >= 70)
            {
                StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 69, 26, 3));
                StatusBadge.BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 217, 119, 6));
                StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 251, 191, 36));
                StatusBadgeText.Text = "MODERATE POSTURE";
                MetricDefenseScore.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 251, 191, 36));
            }
            else
            {
                StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 69, 10, 10));
                StatusBadge.BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 220, 38, 38));
                StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
                StatusBadgeText.Text = "ELEVATED RISK";
                MetricDefenseScore.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
            }

            if (snapshot.HighRiskFindingsCount > 0)
            {
                MetricFlaggedExposures.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
                WatchersCountBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 69, 10, 10));
                WatchersCountBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
                WatchersCountBadgeText.Text = $"{snapshot.HighRiskFindingsCount} FLAGGED";
            }
            else
            {
                MetricFlaggedExposures.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
                WatchersCountBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59));
                WatchersCountBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
                WatchersCountBadgeText.Text = $"{snapshot.WatcherFindings.Count} VERIFIED";
            }

            _watcherItems.Clear();
            foreach (var finding in snapshot.WatcherFindings)
            {
                _watcherItems.Add(new WatcherItemViewModel(finding));
            }

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = snapshot.HighRiskFindingsCount > 0 ? InfoBarSeverity.Warning : InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Defense Posture Evaluated";
            NotificationInfoBar.Message = snapshot.HighRiskFindingsCount > 0
                ? $"Evaluated {snapshot.WatcherFindings.Count} defense watchers. Found {snapshot.HighRiskFindingsCount} flagged exposure(s) requiring attention."
                : $"Evaluated {snapshot.WatcherFindings.Count} defense watchers. All baseline tolerances verified clean.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Evaluation Failed";
            NotificationInfoBar.Message = ex.Message;
        }
        finally
        {
            EvaluateButton.IsEnabled = true;
        }
    }

    private void ExportReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_currentSnapshot is null)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Warning;
            NotificationInfoBar.Title = "No Data";
            NotificationInfoBar.Message = "Please run an evaluation before exporting.";
            return;
        }

        try
        {
            string markdown = _coordinator.GenerateDefensePostureReport(_currentSnapshot);
            var package = new DataPackage();
            package.SetText(markdown);
            Clipboard.SetContent(package);

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Report Exported";
            NotificationInfoBar.Message = "Executive Defense Posture Report copied to clipboard in Markdown format.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Export Failed";
            NotificationInfoBar.Message = ex.Message;
        }
    }

    private void OpenAegis_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("aegis");

    private void OpenRansomware_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("ransomware");

    private void OpenHardening_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("hardening");

    private void OpenEmergency_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("emergency");
}

public sealed class WatcherItemViewModel
{
    public string WatcherId { get; }
    public string Title { get; }
    public string Category { get; }
    public string Severity { get; }
    public string Description { get; }
    public string MitreTechnique { get; }
    public string ObservedDetail { get; }
    public bool IsFlagged { get; }

    public string StatusBadgeText { get; }
    public SolidColorBrush StatusBadgeBackground { get; }
    public SolidColorBrush StatusBadgeBorder { get; }
    public SolidColorBrush StatusBadgeForeground { get; }

    public WatcherItemViewModel(DefenseWatcherFinding finding)
    {
        WatcherId = finding.WatcherId;
        Title = finding.Title;
        Category = finding.Category;
        Severity = finding.Severity;
        Description = finding.Description;
        MitreTechnique = finding.MitreTechnique;
        ObservedDetail = finding.ObservedState;
        IsFlagged = finding.IsFlagged;

        if (finding.IsFlagged)
        {
            StatusBadgeText = finding.Severity.ToUpperInvariant();
            if (finding.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase))
            {
                StatusBadgeBackground = new SolidColorBrush(ColorHelper.FromArgb(255, 69, 10, 10));
                StatusBadgeBorder = new SolidColorBrush(ColorHelper.FromArgb(255, 220, 38, 38));
                StatusBadgeForeground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
            }
            else if (finding.Severity.Equals("High", StringComparison.OrdinalIgnoreCase))
            {
                StatusBadgeBackground = new SolidColorBrush(ColorHelper.FromArgb(255, 69, 26, 3));
                StatusBadgeBorder = new SolidColorBrush(ColorHelper.FromArgb(255, 217, 119, 6));
                StatusBadgeForeground = new SolidColorBrush(ColorHelper.FromArgb(255, 251, 191, 36));
            }
            else
            {
                StatusBadgeBackground = new SolidColorBrush(ColorHelper.FromArgb(255, 30, 27, 75));
                StatusBadgeBorder = new SolidColorBrush(ColorHelper.FromArgb(255, 67, 56, 202));
                StatusBadgeForeground = new SolidColorBrush(ColorHelper.FromArgb(255, 167, 139, 250));
            }
        }
        else
        {
            StatusBadgeText = "CLEAN";
            StatusBadgeBackground = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59));
            StatusBadgeBorder = new SolidColorBrush(ColorHelper.FromArgb(255, 5, 150, 105));
            StatusBadgeForeground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }
    }
}
