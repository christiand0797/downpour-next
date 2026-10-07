using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace Downpour_Desktop.Pages;

public sealed partial class ToolsPage : Page
{
    private readonly ToolsHubCoordinator _coordinator = new();
    private readonly ObservableCollection<OperationalToolCardInfo> _tools = new();
    private ToolsHubSnapshot? _currentSnapshot;

    public ToolsPage()
    {
        InitializeComponent();
        ToolsItemsControl.ItemsSource = _tools;

        Loaded += (_, _) => RefreshUi();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshUi();
        NotificationInfoBar.IsOpen = true;
        NotificationInfoBar.Severity = InfoBarSeverity.Success;
        NotificationInfoBar.Title = "Operations Refreshed";
        NotificationInfoBar.Message = "Operational tools telemetry and system diagnostics refreshed.";
    }

    private async void DiagnosticsButton_Click(object sender, RoutedEventArgs e)
    {
        DiagnosticsButton.IsEnabled = false;
        try
        {
            var snapshot = await Task.Run(() => _coordinator.GetSnapshot());
            _currentSnapshot = snapshot;
            UpdateDiagnostics(snapshot.Diagnostics);

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Diagnostics Completed";
            NotificationInfoBar.Message = $"Executed {snapshot.Diagnostics.Count} operational diagnostic checks. All system tolerances passed.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Diagnostics Failed";
            NotificationInfoBar.Message = ex.Message;
        }
        finally
        {
            DiagnosticsButton.IsEnabled = true;
        }
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
            string markdown = _coordinator.GenerateToolsHubReport(_currentSnapshot);
            var package = new DataPackage();
            package.SetText(markdown);
            Clipboard.SetContent(package);

            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Success;
            NotificationInfoBar.Title = "Report Exported";
            NotificationInfoBar.Message = "Operations & Tools Launchpad report copied to clipboard in Markdown format.";
        }
        catch (Exception ex)
        {
            NotificationInfoBar.IsOpen = true;
            NotificationInfoBar.Severity = InfoBarSeverity.Error;
            NotificationInfoBar.Title = "Export Failed";
            NotificationInfoBar.Message = ex.Message;
        }
    }

    private void LaunchToolButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string routeId } && !string.IsNullOrWhiteSpace(routeId))
        {
            App.NavigateToRoute(routeId);
        }
    }

    private void RefreshUi()
    {
        var snapshot = _coordinator.GetSnapshot();
        _currentSnapshot = snapshot;

        MetricTotalTools.Text = $"{snapshot.TotalTools} Registered";
        MetricSystemHealth.Text = snapshot.OperationalHealth;

        int passed = snapshot.Diagnostics.Count(d => d.IsPassed);
        MetricDiagnosticsPassed.Text = $"{passed}/{snapshot.Diagnostics.Count} Passed";

        UpdateDiagnostics(snapshot.Diagnostics);

        _tools.Clear();
        foreach (var tool in snapshot.Tools)
        {
            _tools.Add(tool);
        }
    }

    private void UpdateDiagnostics(IReadOnlyList<SystemDiagnosticCheck> diagnostics)
    {
        foreach (var diag in diagnostics)
        {
            if (diag.Name.Contains("Platform", StringComparison.OrdinalIgnoreCase))
            {
                DiagOsPlatform.Text = diag.ObservedValue;
                DiagOsDetails.Text = diag.Details;
            }
            else if (diag.Name.Contains("Storage", StringComparison.OrdinalIgnoreCase))
            {
                DiagStorageCapacity.Text = diag.ObservedValue;
                DiagStorageDetails.Text = diag.Details;
            }
            else if (diag.Name.Contains("Network", StringComparison.OrdinalIgnoreCase))
            {
                DiagNetworkStatus.Text = diag.ObservedValue;
                DiagNetworkDetails.Text = diag.Details;
            }
            else if (diag.Name.Contains("Memory", StringComparison.OrdinalIgnoreCase))
            {
                DiagMemoryStatus.Text = diag.ObservedValue;
                DiagMemoryDetails.Text = diag.Details;
            }
        }
    }
}
