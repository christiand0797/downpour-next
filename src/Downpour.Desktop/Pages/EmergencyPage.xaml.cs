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
    private readonly HostIsolationClient _isolationClient = new();
    private readonly ObservableCollection<EmergencyProcessRow> _processRows = [];
    private readonly List<EmergencyLogEntry> _logEntries = [];
    private EmergencySnapshot? _currentSnapshot;
    private int _savedSnapshotsCount = 0;

    public EmergencyPage()
    {
        InitializeComponent();
        EntityDetails.Attach(SuspiciousProcessList, item => item is EmergencyProcessRow p ? DetailDescriptions.EmergencyProcess(p.Process) : null, clickOpensDetails: false);
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

            var isoStatus = await _isolationClient.GetStatusAsync();
            if (isoStatus?.IsIsolated == true)
            {
                StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 185, 28, 28));
                StatusBadgeText.Foreground = new SolidColorBrush(Colors.White);
                StatusBadgeText.Text = $"ISOLATED (UNTIL {isoStatus.ActiveUntilUtc:HH:mm:ss} UTC)";
                AppendLog("Host Network Status", $"Host network isolation is ACTIVE until {isoStatus.ActiveUntilUtc:HH:mm:ss} UTC (inbound/outbound non-loopback dropped, local loopback preserved).", EmergencyLogSeverity.Warning);
            }
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
            DefaultButton = ContentDialogButton.Close,
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

            if (OptIsolateNetwork.IsChecked == true)
            {
                var askIsolateDialog = new ContentDialog
                {
                    Title = "Engage Network Isolation?",
                    Content = new TextBlock
                    {
                        Text = "Panic Lockdown completed. You selected 'Isolate network traffic (Guarded)'.\n\nWould you like to proceed with emergency host network isolation now? (Windows Firewall will drop all non-loopback traffic; Downpour IPC loopback is preserved; auto-expires in 30 minutes).",
                        TextWrapping = TextWrapping.Wrap
                    },
                    PrimaryButtonText = "Proceed to Isolation",
                    CloseButtonText = "Skip",
                    DefaultButton = ContentDialogButton.Close,
                    XamlRoot = XamlRoot
                };

                if (await askIsolateDialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    ActionIsolateBtn_Click(sender, e);
                }
            }
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
        var durationBox = new TextBox { Text = "30", Width = 80, HorizontalAlignment = HorizontalAlignment.Left };
        var lockBox = new CheckBox { Content = "Lock Windows session immediately (user32.dll)", IsChecked = false };
        var reasonBox = new TextBox { Text = "Incident containment", PlaceholderText = "Reason for host isolation" };

        var inputStack = new StackPanel { Spacing = 10 };
        inputStack.Children.Add(new TextBlock { Text = "Emergency Host Network Isolation (DN-008 Phase 5)", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        inputStack.Children.Add(new TextBlock { Text = "All inbound and outbound non-loopback network packets will be blocked by Windows Firewall.\nLocal loopback (127.0.0.1, ::1) is preserved so Downpour remains operational.\nIsolation MUST auto-expire (5 to 1440 minutes). Permanent isolation is strictly prohibited.", TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Colors.LightGray), FontSize = 12 });
        inputStack.Children.Add(new TextBlock { Text = "Duration in minutes (5 - 1440):", Margin = new Thickness(0, 4, 0, 0) });
        inputStack.Children.Add(durationBox);
        inputStack.Children.Add(lockBox);
        inputStack.Children.Add(new TextBlock { Text = "Operator audit reason:", Margin = new Thickness(0, 4, 0, 0) });
        inputStack.Children.Add(reasonBox);

        var requestDialog = new ContentDialog
        {
            Title = "Request Host Network Isolation",
            Content = inputStack,
            PrimaryButtonText = "Preview Isolation",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot
        };

        if (await requestDialog.ShowAsync() != ContentDialogResult.Primary)
        {
            AppendLog("Host Isolation", "Isolation request cancelled by operator.", EmergencyLogSeverity.Info);
            return;
        }

        if (!int.TryParse(durationBox.Text.Trim(), out int durationMinutes) || durationMinutes < 5 || durationMinutes > 1440)
        {
            var invalidDialog = new ContentDialog
            {
                Title = "Invalid Duration",
                Content = new TextBlock { Text = "Duration must be an integer between 5 and 1440 minutes (24 hours). Permanent isolation is strictly prohibited." },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await invalidDialog.ShowAsync();
            return;
        }

        bool lockWorkstation = lockBox.IsChecked == true;
        string reason = string.IsNullOrWhiteSpace(reasonBox.Text) ? "Incident containment" : reasonBox.Text.Trim();

        AppendLog("Host Isolation", $"Requesting preview from sensor service ({durationMinutes} minutes)...", EmergencyLogSeverity.Info);
        var preview = await _isolationClient.PreviewIsolateAsync(durationMinutes, lockWorkstation, reason);

        if (preview is null)
        {
            AppendLog("Host Isolation", "The sensor service did not respond. Verify service is running.", EmergencyLogSeverity.Critical);
            var unreachDialog = new ContentDialog
            {
                Title = "Service Unreachable",
                Content = new TextBlock { Text = "The Downpour sensor service did not respond. Host isolation requires the elevated background service." },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await unreachDialog.ShowAsync();
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            AppendLog("Host Isolation Denied", preview.Message, EmergencyLogSeverity.Critical);
            var deniedDialog = new ContentDialog
            {
                Title = "Isolation Denied",
                Content = new TextBlock { Text = preview.Message },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Isolation Duration: {p.DurationMinutes} minutes (Expires {p.ExpiresAtUtc:HH:mm:ss} UTC)\n" +
                          $"Workstation Lock: {(p.LockWorkstation ? "Yes" : "No")}\n\n" +
                          $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          $"Rollback / Auto-Expiry:\n• {string.Join("\n• ", p.RollbackSteps)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Are you sure you want to isolate this host now?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm Emergency Host Isolation",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "CONFIRM ISOLATION",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot
        };

        if (await confirmDialog.ShowAsync() != ContentDialogResult.Primary || p.ConsentToken is null)
        {
            AppendLog("Host Isolation", "Isolation confirmation cancelled. No changes made.", EmergencyLogSeverity.Info);
            return;
        }

        AppendLog("Host Isolation", "Engaging emergency host isolation...", EmergencyLogSeverity.Warning);
        var outcome = await _isolationClient.IsolateAsync(p.ConsentToken, p.DurationMinutes, p.LockWorkstation, reason);

        if (outcome?.Accepted == true)
        {
            StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 185, 28, 28));
            StatusBadgeText.Foreground = new SolidColorBrush(Colors.White);
            StatusBadgeText.Text = $"ISOLATED (UNTIL {outcome.ActiveUntilUtc:HH:mm:ss} UTC)";

            string rulesStr = outcome.RulesCreated is not null ? string.Join(", ", outcome.RulesCreated) : "Downpour isolation rules";
            AppendLog("Host Isolation", $"HOST ISOLATED. Block rules active until {outcome.ActiveUntilUtc:HH:mm:ss} UTC. Rules: {rulesStr}.", EmergencyLogSeverity.Critical);

            var successDialog = new ContentDialog
            {
                Title = "Host Isolation Engaged",
                Content = new TextBlock
                {
                    Text = $"Emergency host network isolation is now active.\n\nAll non-loopback inbound and outbound network traffic is blocked.\nLoopback (127.0.0.1, ::1) is preserved for Downpour IPC.\n\nAutomatic release scheduled for {outcome.ActiveUntilUtc:HH:mm:ss} UTC ({durationMinutes} minutes).\nYou can also release isolation manually at any time.",
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await successDialog.ShowAsync();
        }
        else
        {
            AppendLog("Host Isolation Failed", outcome?.Message ?? "No response received.", EmergencyLogSeverity.Critical);
            var failDialog = new ContentDialog
            {
                Title = "Isolation Failed",
                Content = new TextBlock { Text = outcome?.Message ?? "Failed to engage host isolation." },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await failDialog.ShowAsync();
        }
    }

    private async void ActionRestoreBtn_Click(object sender, RoutedEventArgs e)
    {
        AppendLog("Host Isolation", "Requesting release preview from sensor service...", EmergencyLogSeverity.Info);
        var preview = await _isolationClient.PreviewReleaseAsync("Operator manual release");

        if (preview is null)
        {
            AppendLog("Host Isolation", "The sensor service did not respond.", EmergencyLogSeverity.Critical);
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            AppendLog("Release Denied", preview.Message, EmergencyLogSeverity.Warning);
            var deniedDialog = new ContentDialog
            {
                Title = "Release Preview Denied",
                Content = new TextBlock { Text = preview.Message },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Restore full host network connectivity now?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm Network Restoration",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "Restore Connectivity",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot
        };

        if (await confirmDialog.ShowAsync() != ContentDialogResult.Primary || p.ConsentToken is null)
        {
            AppendLog("Host Isolation", "Restoration cancelled by operator.", EmergencyLogSeverity.Info);
            return;
        }

        AppendLog("Host Isolation", "Releasing host isolation rules...", EmergencyLogSeverity.Info);
        var outcome = await _isolationClient.ReleaseAsync(p.ConsentToken, "Operator manual release");

        if (outcome?.Accepted == true)
        {
            StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 69, 10, 10));
            StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
            StatusBadgeText.Text = "ARMED";

            AppendLog("Host Isolation", "Host isolation rules removed. Normal network connectivity restored.", EmergencyLogSeverity.Success);

            var successDialog = new ContentDialog
            {
                Title = "Network Connectivity Restored",
                Content = new TextBlock { Text = "Host isolation firewall rules have been removed and the auto-expiry timer cancelled. Normal network connectivity is restored." },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await successDialog.ShowAsync();
        }
        else
        {
            AppendLog("Release Failed", outcome?.Message ?? "Failed to release isolation.", EmergencyLogSeverity.Critical);
            var failDialog = new ContentDialog
            {
                Title = "Release Failed",
                Content = new TextBlock { Text = outcome?.Message ?? "Failed to release host isolation." },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await failDialog.ShowAsync();
        }
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
            DefaultButton = ContentDialogButton.Close,
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
