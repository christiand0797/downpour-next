using System.Collections.ObjectModel;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour_Desktop.Pages;

public sealed partial class EmergencyPage : Page
{
    private readonly EmergencyResponseCoordinator _coordinator = new();
    private readonly ObservableCollection<EmergencyProcessRow> _processRows = [];
    private readonly List<EmergencyLogEntry> _logEntries = [];
    private EmergencySnapshot? _currentSnapshot;
    private int _savedSnapshotsCount = 0;

    public EmergencyPage()
    {
        InitializeComponent();
        SuspiciousProcessList.ItemsSource = _processRows;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = EvaluateCurrentPostureAsync();
    }

    private async Task EvaluateCurrentPostureAsync()
    {
        try
        {
            StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 69, 10, 10));
            StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
            StatusBadgeText.Text = "ARMED";

            AppendLog("Posture Assessment", "Inspecting volatile processes and active network sessions...", EmergencyLogSeverity.Info);

            var snapshot = await _coordinator.CaptureSnapshotAsync();
            _savedSnapshotsCount++;
            UpdateSnapshotView(snapshot);

            AppendLog("Posture Assessment", $"Assessment complete: {snapshot.ProcessCount} processes, {snapshot.SuspiciousProcessCount} suspicious flags, {snapshot.ConnectionCount} active TCP connections.",
                snapshot.SuspiciousProcessCount > 0 ? EmergencyLogSeverity.Warning : EmergencyLogSeverity.Success);
        }
        catch (Exception ex)
        {
            AppendLog("Posture Assessment Failed", ex.Message, EmergencyLogSeverity.Critical);
        }
    }

    private void UpdateSnapshotView(EmergencySnapshot snapshot)
    {
        _currentSnapshot = snapshot;

        // Metrics
        MetricTotalProcesses.Text = snapshot.ProcessCount.ToString();
        MetricActiveConnections.Text = snapshot.ConnectionCount.ToString();
        MetricSuspiciousProcs.Text = snapshot.SuspiciousProcessCount.ToString();
        MetricSavedSnapshots.Text = _savedSnapshotsCount.ToString();

        if (snapshot.SuspiciousProcessCount > 0)
        {
            MetricSuspiciousProcs.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 239, 68, 68));
            ProcCountBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 127, 29, 29));
            ProcCountBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 252, 165, 165));
            ProcCountBadgeText.Text = $"{snapshot.SuspiciousProcessCount} FLAGGED";
        }
        else
        {
            MetricSuspiciousProcs.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
            ProcCountBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 95, 70));
            ProcCountBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 110, 231, 183));
            ProcCountBadgeText.Text = "0 DETECTED";
        }

        // Details card
        SnapshotIdText.Text = $"Response ID: {snapshot.SnapshotId}";
        SnapshotTimestampText.Text = $"Captured: {snapshot.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC";
        SnapshotHostText.Text = $"Host: {snapshot.MachineName} ({snapshot.OsVersion})";
        SnapshotSealText.Text = snapshot.ForensicSealSha256;
        SnapshotPathText.Text = string.IsNullOrEmpty(snapshot.SnapshotFilePath) ? "In-Memory / Protected" : snapshot.SnapshotFilePath;

        // Process list
        _processRows.Clear();
        var suspiciousProcs = snapshot.Processes.Where(p => p.IsSuspicious).ToList();
        if (suspiciousProcs.Count == 0)
        {
            EmptyProcsNotice.Visibility = Visibility.Visible;
            SuspiciousProcessList.Visibility = Visibility.Collapsed;
        }
        else
        {
            EmptyProcsNotice.Visibility = Visibility.Collapsed;
            SuspiciousProcessList.Visibility = Visibility.Visible;
            foreach (var proc in suspiciousProcs)
            {
                _processRows.Add(new EmergencyProcessRow(proc));
            }
        }
    }

    private async void PanicButton_Click(object sender, RoutedEventArgs e)
    {
        var confirmDialog = new ContentDialog
        {
            Title = "CONFIRM EMERGENCY LOCKDOWN",
            Content = new TextBlock
            {
                Text = "Are you sure you want to activate Emergency Panic Lockdown?\n\nThis procedure will:\n1. Capture and seal a point-in-time system snapshot\n2. Catalog all volatile processes and active connections\n3. Evaluate host network containment policy (DN-008)\n4. Screen and log suspicious exploitation indicators\n\nDestructive network and process changes remain safely guarded under least-privilege policy.",
                TextWrapping = TextWrapping.Wrap
            },
            PrimaryButtonText = "ACTIVATE LOCKDOWN",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot
        };

        var choice = await confirmDialog.ShowAsync();
        if (choice != ContentDialogResult.Primary)
        {
            AppendLog("Panic Lockdown", "Emergency lockdown was cancelled by the user.", EmergencyLogSeverity.Info);
            return;
        }

        try
        {
            PanicButton.IsEnabled = false;
            StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 220, 38, 38));
            StatusBadgeText.Foreground = new SolidColorBrush(Colors.White);
            StatusBadgeText.Text = "LOCKDOWN ACTIVE";

            AppendLog("Panic Lockdown", "EMERGENCY PANIC LOCKDOWN INITIATED.", EmergencyLogSeverity.Critical);

            var outcome = await _coordinator.ExecuteFullLockdownAsync();
            _savedSnapshotsCount++;

            foreach (var action in outcome.ActionResults)
            {
                var severity = action.Status == EmergencyActionStatus.Completed ? EmergencyLogSeverity.Success :
                               action.Status == EmergencyActionStatus.GuardedPendingAuthorization ? EmergencyLogSeverity.Warning :
                               EmergencyLogSeverity.Critical;

                AppendLog(action.ActionTitle, action.Details, severity);
            }

            if (_currentSnapshot is not null)
            {
                UpdateSnapshotView(_currentSnapshot);
            }

            AppendLog("Panic Lockdown", outcome.Summary, EmergencyLogSeverity.Success);

            var resultDialog = new ContentDialog
            {
                Title = "Emergency Lockdown Executed",
                Content = new TextBlock
                {
                    Text = $"Emergency lockdown sequence completed.\n\nResponse ID: {outcome.ResponseId}\nSnapshot Path: {outcome.SnapshotPath}\nSuspicious Processes: {outcome.SuspiciousProcessesCount}\n\nHost network isolation and process termination were logged and guarded under DN-008 least-privilege policy.",
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await resultDialog.ShowAsync();
        }
        catch (Exception ex)
        {
            AppendLog("Lockdown Failure", ex.Message, EmergencyLogSeverity.Critical);
        }
        finally
        {
            PanicButton.IsEnabled = true;
        }
    }

    private async void SnapshotButton_Click(object sender, RoutedEventArgs e)
    {
        await TakeSnapshotInternalAsync();
    }

    private async void ActionSnapshotBtn_Click(object sender, RoutedEventArgs e)
    {
        await TakeSnapshotInternalAsync();
    }

    private async Task TakeSnapshotInternalAsync()
    {
        try
        {
            AppendLog("System Snapshot", "Capturing volatile system snapshot...", EmergencyLogSeverity.Info);
            var snapshot = await _coordinator.CaptureSnapshotAsync();
            _savedSnapshotsCount++;
            UpdateSnapshotView(snapshot);
            AppendLog("System Snapshot", $"Snapshot preserved: {snapshot.ProcessCount} processes, {snapshot.ConnectionCount} connections. SHA-256: {snapshot.ForensicSealSha256[..12]}...", EmergencyLogSeverity.Success);
        }
        catch (Exception ex)
        {
            AppendLog("System Snapshot", $"Failed: {ex.Message}", EmergencyLogSeverity.Critical);
        }
    }

    private async void ActionIsolateBtn_Click(object sender, RoutedEventArgs e)
    {
        var result = await _coordinator.ExecuteActionAsync(EmergencyActionType.IsolateNetwork, _currentSnapshot);
        AppendLog(result.ActionTitle, result.Details, EmergencyLogSeverity.Warning);

        var dialog = new ContentDialog
        {
            Title = "Network Isolation Guarded (DN-008)",
            Content = new TextBlock
            {
                Text = "Host network isolation (disabling network adapters / applying total firewall block) is guarded under least-privilege policy.\n\nSystem-altering actions require an authorized Action Broker token under DN-008. In read-only mode, the isolation action was logged and validated without disconnecting your host.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "Understood",
            XamlRoot = XamlRoot
        };
        await dialog.ShowAsync();
    }

    private async void ActionRestoreBtn_Click(object sender, RoutedEventArgs e)
    {
        var result = await _coordinator.ExecuteActionAsync(EmergencyActionType.RestoreNetwork, _currentSnapshot);
        AppendLog(result.ActionTitle, result.Details, EmergencyLogSeverity.Info);

        var dialog = new ContentDialog
        {
            Title = "Restore Network Guarded (DN-008)",
            Content = new TextBlock
            {
                Text = "Network restoration is guarded under Action Broker policy (DN-008).\n\nIf you have emergency firewall blocks configured, modifying adapter states requires elevated Action Broker approval.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "Understood",
            XamlRoot = XamlRoot
        };
        await dialog.ShowAsync();
    }

    private async void ActionKillBtn_Click(object sender, RoutedEventArgs e)
    {
        int count = _currentSnapshot?.SuspiciousProcessCount ?? 0;
        var result = await _coordinator.ExecuteActionAsync(EmergencyActionType.TerminateSuspicious, _currentSnapshot);
        AppendLog(result.ActionTitle, result.Details, EmergencyLogSeverity.Warning);

        var dialog = new ContentDialog
        {
            Title = "Process Termination Guarded (DN-008)",
            Content = new TextBlock
            {
                Text = $"Process termination ({count} suspicious process(es) identified) is guarded under least-privilege policy.\n\nTerminating running processes without an audited Action Broker (DN-008) can destabilize system services. Termination requests require operator review and elevated broker policy.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "Understood",
            XamlRoot = XamlRoot
        };
        await dialog.ShowAsync();
    }

    private async void ActionForensicsBtn_Click(object sender, RoutedEventArgs e)
    {
        var result = await _coordinator.ExecuteActionAsync(EmergencyActionType.CollectForensics, _currentSnapshot);
        AppendLog(result.ActionTitle, result.Details, EmergencyLogSeverity.Success);

        var dialog = new ContentDialog
        {
            Title = "Volatile Forensics Evidence Cataloged",
            Content = new TextBlock
            {
                Text = "Volatile forensic evidence has been captured and sealed.\n\nProcesses, memory footprints, network sockets, and execution paths have been timestamped and hashed with SHA-256 for chain-of-custody verification.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "OK",
            XamlRoot = XamlRoot
        };
        await dialog.ShowAsync();
    }

    private async void LockWorkstationButton_Click(object sender, RoutedEventArgs e)
    {
        await LockWorkstationInternalAsync();
    }

    private async void ActionLockBtn_Click(object sender, RoutedEventArgs e)
    {
        await LockWorkstationInternalAsync();
    }

    private async Task LockWorkstationInternalAsync()
    {
        var confirmDialog = new ContentDialog
        {
            Title = "Lock Workstation Session",
            Content = new TextBlock
            {
                Text = "Lock your Windows workstation session now?\n\nThis immediately locks the current desktop session via Windows user32.dll, requiring your Windows password, PIN, or Hello credential to resume.",
                TextWrapping = TextWrapping.Wrap
            },
            PrimaryButtonText = "Lock Session",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot
        };

        var choice = await confirmDialog.ShowAsync();
        if (choice != ContentDialogResult.Primary)
        {
            AppendLog("Lock Workstation", "Lock workstation cancelled by user.", EmergencyLogSeverity.Info);
            return;
        }

        var result = await _coordinator.ExecuteActionAsync(EmergencyActionType.LockWorkstation);
        AppendLog(result.ActionTitle, result.Details, result.Status == EmergencyActionStatus.Completed ? EmergencyLogSeverity.Success : EmergencyLogSeverity.Critical);
    }

    private async void ExportIrReportButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_currentSnapshot is null)
            {
                _currentSnapshot = await _coordinator.CaptureSnapshotAsync();
                _savedSnapshotsCount++;
            }

            string reportContent = _coordinator.GenerateIncidentResponseReport(_currentSnapshot, _logEntries);
            string desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string filePath = Path.Combine(desktopDir, $"Downpour_Incident_Response_{_currentSnapshot.SnapshotId}.md");

            await File.WriteAllTextAsync(filePath, reportContent);
            AppendLog("Export IR Report", $"Incident Response markdown report saved to Desktop: {Path.GetFileName(filePath)}", EmergencyLogSeverity.Success);

            var dialog = new ContentDialog
            {
                Title = "Incident Response Report Exported",
                Content = new TextBlock
                {
                    Text = $"The Incident Response (IR) report has been exported to your Desktop:\n\n{filePath}\n\nIncludes executive summary, forensic SHA-256 seal, flagged processes, and audit log.",
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await dialog.ShowAsync();
        }
        catch (Exception ex)
        {
            AppendLog("Export IR Report", $"Export failed: {ex.Message}", EmergencyLogSeverity.Critical);
        }
    }

    private void ClearLogButton_Click(object sender, RoutedEventArgs e)
    {
        _logEntries.Clear();
        LogTextBox.Text = string.Empty;
        AppendLog("Event Log", "Emergency event log cleared.", EmergencyLogSeverity.Info);
    }

    private void AppendLog(string action, string message, EmergencyLogSeverity severity)
    {
        var entry = new EmergencyLogEntry(DateTimeOffset.UtcNow, severity, action, message);
        _logEntries.Add(entry);

        string severityTag = severity switch
        {
            EmergencyLogSeverity.Success => "[OK]",
            EmergencyLogSeverity.Warning => "[WARN]",
            EmergencyLogSeverity.Critical => "[CRIT]",
            _ => "[INFO]"
        };

        string logLine = $"[{entry.TimestampUtc:HH:mm:ss}] {severityTag} {action}: {message}\n";
        LogTextBox.Text = logLine + LogTextBox.Text;
    }
}

public sealed class EmergencyProcessRow(EmergencyProcessInfo proc)
{
    public EmergencyProcessInfo Process => proc;

    public string ProcessName => proc.ProcessName;
    public string PidSummary => $"PID {proc.ProcessId}";
    public string ExecutablePath => string.IsNullOrEmpty(proc.ExecutablePath) ? "(Path unavailable / Protected)" : proc.ExecutablePath;
    public string SuspicionReason => proc.SuspicionReason;
    public string MitreTechnique => proc.MitreTechnique;
    public string MemorySummary => $"{proc.WorkingSetBytes / (1024.0 * 1024.0):F1} MB";
}
