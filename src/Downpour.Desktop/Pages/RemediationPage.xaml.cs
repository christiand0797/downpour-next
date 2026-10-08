using System.Globalization;
using System.Runtime.InteropServices;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Storage.Pickers;

namespace Downpour_Desktop.Pages;

/// <summary>
/// DN-008 phase 1: user-selected quarantine and confirmed restore through the service's action pipe. The page never touches
/// the file itself; it shows the service's preview (resolved path, size, SHA-256) and returns the one-time consent token.
/// </summary>
public sealed partial class RemediationPage : Page
{
    private readonly QuarantineClient _client = new();
    private readonly HostIsolationClient _isolationClient = new();
    private bool _busy;

    public RemediationPage()
    {
        InitializeComponent();
        LiveRefresh.Attach(this, () => RefreshAsync(quiet: true));
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync(bool quiet = false)
    {
        if (_busy) return;
        SetBusy(true, "Loading remediation state…");
        var response = await _client.ListAsync();
        if (response is null)
        {
            await App.EnsureSensorServiceAsync();
            response = await _client.ListAsync();
        }
        var isoStatus = await _isolationClient.GetStatusAsync();
        SetBusy(false, "");
        if (response is null)
        {
            StatusText.Text = "The sensor service is not reachable. Remediation needs the service that this desktop started.";
            QuarantineButton.IsEnabled = false;
            TerminateProcessButton.IsEnabled = false;
            BlockIpButton.IsEnabled = false;
            BlockUsbDeviceButton.IsEnabled = false;
            IsolateHostButton.IsEnabled = false;
            ReleaseIsolationButton.IsEnabled = false;
            return;
        }
        if (!response.Accepted)
        {
            StatusText.Text = response.Message;
            QuarantineButton.IsEnabled = false;
            TerminateProcessButton.IsEnabled = false;
            BlockIpButton.IsEnabled = false;
            BlockUsbDeviceButton.IsEnabled = false;
            IsolateHostButton.IsEnabled = false;
            ReleaseIsolationButton.IsEnabled = false;
            return;
        }
        QuarantineButton.IsEnabled = response.ActionsEnabled;
        TerminateProcessButton.IsEnabled = response.ActionsEnabled;
        BlockIpButton.IsEnabled = response.ActionsEnabled;
        BlockUsbDeviceButton.IsEnabled = response.ActionsEnabled;
        IsolateHostButton.IsEnabled = response.ActionsEnabled;
        ReleaseIsolationButton.IsEnabled = response.ActionsEnabled;
        StatusText.Text = response.ActionsEnabled ? "" : "Response actions are turned off in Settings.";

        if (isoStatus?.IsIsolated == true)
        {
            HostIsolationBar.Message = $"Host network is isolated until {isoStatus.ActiveUntilUtc:HH:mm:ss} UTC. All non-loopback network packets are dropped; local loopback IPC is preserved.";
            HostIsolationBar.IsOpen = true;
            ReleaseIsolationButton.Visibility = Visibility.Visible;
        }
        else
        {
            HostIsolationBar.IsOpen = false;
            ReleaseIsolationButton.Visibility = Visibility.Collapsed;
        }

        if (response.RecoveryNotes is { Count: > 0 } notes)
        {
            RecoveryBar.Message = string.Join("\n", notes);
            RecoveryBar.IsOpen = true;
        }
        Render(response.Items ?? [], response.ActionsEnabled);
    }

    private void Render(IReadOnlyList<QuarantineItem> items, bool actionsEnabled)
    {
        ItemsPanel.Children.Clear();
        EmptyText.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var item in items)
        {
            var details = new StackPanel { Spacing = 3 };
            details.Children.Add(new TextBlock { Text = item.FileName, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            details.Children.Add(Secondary($"From {item.OriginalPath}"));
            details.Children.Add(Secondary($"{FormatSize(item.Size)} · quarantined {item.QuarantinedAtUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)}"));
            details.Children.Add(new TextBlock { Text = item.Sha256, FontFamily = new FontFamily("Consolas"), FontSize = 11, IsTextSelectionEnabled = true, Foreground = SecondaryBrush() });
            if (item.RestoredAtUtc is { } restored)
                details.Children.Add(Secondary($"Restored {restored.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)} to {item.RestoredTo}"));

            var row = new Grid { ColumnSpacing = 12 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.Children.Add(details);
            if (item.RestoredAtUtc is null)
            {
                var buttons = new StackPanel { Spacing = 6, VerticalAlignment = VerticalAlignment.Center };
                var restore = new Button { Content = "Restore", IsEnabled = actionsEnabled, Tag = item };
                restore.Click += async (_, _) => await RestoreAsync(item, alternate: false);
                var restoreAs = new Button { Content = "Restore as…", IsEnabled = actionsEnabled, Tag = item };
                restoreAs.Click += async (_, _) => await RestoreAsync(item, alternate: true);
                buttons.Children.Add(restore);
                buttons.Children.Add(restoreAs);
                Grid.SetColumn(buttons, 1);
                row.Children.Add(buttons);
            }
            ItemsPanel.Children.Add(new Border
            {
                Padding = new Thickness(14),
                CornerRadius = new CornerRadius(10),
                BorderThickness = new Thickness(1),
                BorderBrush = new SolidColorBrush(Windows.UI.Color.FromArgb(0x57, 0x38, 0xB9, 0xD1)),
                Background = new SolidColorBrush(Windows.UI.Color.FromArgb(0xC8, 0x08, 0x11, 0x1E)),
                Child = row,
            });
        }
    }

    private async void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        Windows.Storage.StorageFile? file;
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            file = await picker.PickSingleFileAsync();
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            StatusText.Text = $"The file picker could not be opened: {exception.Message}";
            return;
        }
        if (file is null || string.IsNullOrEmpty(file.Path)) return;

        SetBusy(true, "Hashing the file in the service…");
        var preview = await _client.PreviewQuarantineAsync(file.Path);
        SetBusy(false, "");
        if (preview is null) { StatusText.Text = "The sensor service did not respond."; return; }
        if (!preview.Accepted || preview.Preview?.ConsentToken is null) { StatusText.Text = preview.Message; return; }

        var p = preview.Preview;
        var confirmed = await ConfirmAsync("Quarantine this file?",
            $"{p.TargetPath}\n\nSize: {FormatSize(p.Size)}\nSHA-256: {p.Sha256}\n\nThe file will be encrypted into Downpour's quarantine store and removed from its folder. You can restore it later from this page. Programs that use this file may stop working.",
            "Quarantine");
        if (!confirmed) { StatusText.Text = "Cancelled. Nothing was changed."; return; }

        SetBusy(true, "Quarantining…");
        var result = await _client.QuarantineAsync(p.TargetPath, p.ConsentToken);
        SetBusy(false, "");
        StatusText.Text = result?.Message ?? "The sensor service did not respond. Check the list before trying again.";
        await RefreshAsync();
        StatusText.Text = result?.Message ?? StatusText.Text;
    }

    private async Task RestoreAsync(QuarantineItem item, bool alternate)
    {
        if (_busy) return;
        string? restorePath = null;
        if (alternate)
        {
            try
            {
                var picker = new FileSavePicker { SuggestedFileName = item.FileName };
                var extension = Path.GetExtension(item.FileName);
                picker.FileTypeChoices.Add("Original type", [string.IsNullOrEmpty(extension) ? "." : extension]);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
                var target = await picker.PickSaveFileAsync();
                if (target is null) return;
                restorePath = target.Path;
                // The save picker may create an empty placeholder; restore never overwrites, so remove only that empty file.
                if (File.Exists(restorePath) && new FileInfo(restorePath).Length == 0) File.Delete(restorePath);
            }
            catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException or IOException)
            {
                StatusText.Text = $"The save dialog could not be used: {exception.Message}";
                return;
            }
        }

        SetBusy(true, "Checking the restore location…");
        var preview = await _client.PreviewRestoreAsync(item.ObjectId, restorePath);
        SetBusy(false, "");
        if (preview is null) { StatusText.Text = "The sensor service did not respond."; return; }
        if (!preview.Accepted || preview.Preview?.ConsentToken is null) { StatusText.Text = preview.Message; return; }

        var confirmed = await ConfirmAsync("Restore this file?",
            $"{item.FileName} will be decrypted, verified against its recorded SHA-256, and written to:\n\n{preview.Preview.TargetPath}\n\nOnly restore a file you are sure is safe. It was quarantined for a reason: {item.Reason}.",
            "Restore");
        if (!confirmed) { StatusText.Text = "Cancelled. Nothing was changed."; return; }

        SetBusy(true, "Restoring…");
        var result = await _client.RestoreAsync(item.ObjectId, restorePath, preview.Preview.ConsentToken);
        SetBusy(false, "");
        var message = result?.Message ?? "The sensor service did not respond.";
        await RefreshAsync();
        StatusText.Text = message;
    }

    private async Task<bool> ConfirmAsync(string title, string body, string primary)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new ScrollViewer { Content = new TextBlock { Text = body, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true }, MaxHeight = 360 },
            PrimaryButtonText = primary,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async void TerminateProcess_Click(object sender, RoutedEventArgs e)
    {
        var inputTextBox = new TextBox { PlaceholderText = "Enter target process PID (e.g. 1234)" };
        var inputDialog = new ContentDialog
        {
            Title = "Terminate Process by PID",
            Content = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new TextBlock { Text = "Enter the Process ID (PID) of the suspicious process to review and terminate under Action Broker policy (DN-008 Phase 2):", TextWrapping = TextWrapping.Wrap },
                    inputTextBox
                }
            },
            PrimaryButtonText = "Inspect & Preview",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await inputDialog.ShowAsync() != ContentDialogResult.Primary) return;
        if (!int.TryParse(inputTextBox.Text.Trim(), out var pid) || pid <= 0)
        {
            var invalidPidDialog = new ContentDialog
            {
                Title = "Invalid PID",
                Content = "Please enter a valid positive integer process ID.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await invalidPidDialog.ShowAsync();
            return;
        }

        DateTimeOffset startTime = DateTimeOffset.MinValue;
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            startTime = proc.StartTime.ToUniversalTime();
        }
        catch (Exception ex)
        {
            var notFoundDialog = new ContentDialog
            {
                Title = "Process Not Found",
                Content = $"Process with PID {pid} is not currently running ({ex.Message}).",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await notFoundDialog.ShowAsync();
            return;
        }

        var client = new ProcessTerminationClient();
        var preview = await client.PreviewTerminateAsync(pid, startTime);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await client.PreviewTerminateAsync(pid, startTime);
        }

        if (preview is null)
        {
            var unreachDialog = new ContentDialog
            {
                Title = "Service Unreachable",
                Content = "The process termination action service endpoint is not reachable.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await unreachDialog.ShowAsync();
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Termination Denied",
                Content = preview.Message,
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Process: {p.ProcessName} (PID {p.ProcessId})\n" +
                          $"Path: {p.ImagePath}\n" +
                          $"Started: {p.StartTimeUtc:yyyy-MM-dd HH:mm:ss} UTC\n\n" +
                          $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Are you sure you want to terminate this process?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm Process Termination (DN-008 Phase 2)",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "Terminate Process",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary && p.ConsentToken is not null)
        {
            SetBusy(true, $"Terminating process {p.ProcessName} (PID {pid})...");
            var outcome = await client.TerminateAsync(pid, startTime, p.ConsentToken);
            SetBusy(false, "");

            var outcomeDialog = new ContentDialog
            {
                Title = outcome?.Accepted == true ? "Process Terminated" : "Termination Failed",
                Content = outcome?.Message ?? "No response received from action service.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await outcomeDialog.ShowAsync();
        }
    }

    private async void BlockIp_Click(object sender, RoutedEventArgs e)
    {
        var ipBox = new TextBox { PlaceholderText = "e.g. 198.51.100.1 or 2001:db8::1" };
        var durationCombo = new ComboBox
        {
            ItemsSource = new[] { "1 hour (60 min)", "24 hours (1440 min)", "7 days (10080 min)" },
            SelectedIndex = 1
        };
        var reasonBox = new TextBox { PlaceholderText = "Optional reason (e.g. C2 indicator, port scan)" };

        var dialog = new ContentDialog
        {
            Title = "Block Remote IP (DN-008 Phase 3)",
            Content = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new TextBlock { Text = "Enter a specific remote IP address to block via Windows Firewall. Local network and critical services are strictly protected to prevent network lockout.", TextWrapping = TextWrapping.Wrap },
                    new TextBlock { Text = "Remote IP Address:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    ipBox,
                    new TextBlock { Text = "Block Duration:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    durationCombo,
                    new TextBlock { Text = "Reason:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    reasonBox
                }
            },
            PrimaryButtonText = "Inspect & Preview",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

        var ip = ipBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(ip)) return;

        int durationMinutes = durationCombo.SelectedIndex switch
        {
            0 => 60,
            1 => 1440,
            2 => 10080,
            _ => 1440
        };

        var reason = reasonBox.Text.Trim();
        var client = new FirewallActionClient();
        var preview = await client.PreviewBlockIpAsync(ip, durationMinutes, reason);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await client.PreviewBlockIpAsync(ip, durationMinutes, reason);
        }

        if (preview is null)
        {
            var unreachDialog = new ContentDialog
            {
                Title = "Service Unreachable",
                Content = "The firewall action service endpoint is not reachable.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await unreachDialog.ShowAsync();
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Block Denied",
                Content = preview.Message,
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Target IP: {p.TargetIp}\n" +
                          $"Duration: {(p.DurationMinutes > 0 ? $"{p.DurationMinutes} minutes" : "Permanent")}\n\n" +
                          $"Rules to Create:\n• {string.Join("\n• ", p.RulesAffected)}\n\n" +
                          $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Are you sure you want to block this remote IP?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm Firewall Remote IP Block",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "Block IP",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary && p.ConsentToken is not null)
        {
            SetBusy(true, $"Blocking remote IP {p.TargetIp}...");
            var outcome = await client.BlockIpAsync(p.TargetIp!, p.ConsentToken, p.DurationMinutes, reason);
            SetBusy(false, "");

            var outcomeDialog = new ContentDialog
            {
                Title = outcome?.Accepted == true ? "Firewall Rules Created" : "Block Failed",
                Content = outcome?.Message ?? "No response received from action service.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await outcomeDialog.ShowAsync();
        }
    }

    private async void BlockUsbDevice_Click(object sender, RoutedEventArgs e)
    {
        var deviceIdBox = new TextBox { PlaceholderText = "Enter USB Device ID or Drive Letter (e.g. E: or Disk&Ven_SanDisk...)" };
        var friendlyNameBox = new TextBox { PlaceholderText = "Optional friendly name (e.g. Suspicious Flash Drive)" };
        var reasonBox = new TextBox { PlaceholderText = "Optional reason (e.g. Unauthorized USB drive)" };

        var inputDialog = new ContentDialog
        {
            Title = "Block USB Device Instance",
            Content = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new TextBlock { Text = "Enter the USB device instance ID or drive letter to inspect and block under Action Broker policy (DN-008 Phase 4):", TextWrapping = TextWrapping.Wrap },
                    new TextBlock { Text = "Device ID / Drive Letter:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    deviceIdBox,
                    new TextBlock { Text = "Friendly Name:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    friendlyNameBox,
                    new TextBlock { Text = "Reason:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    reasonBox
                }
            },
            PrimaryButtonText = "Inspect & Preview",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await inputDialog.ShowAsync() != ContentDialogResult.Primary) return;

        var devId = deviceIdBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(devId)) return;

        var friendlyName = string.IsNullOrWhiteSpace(friendlyNameBox.Text) ? null : friendlyNameBox.Text.Trim();
        var reason = string.IsNullOrWhiteSpace(reasonBox.Text) ? "Operator blocked USB device from Remediation page." : reasonBox.Text.Trim();

        var client = new UsbActionClient();
        var preview = await client.PreviewBlockDeviceAsync(devId, friendlyName, reason);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await client.PreviewBlockDeviceAsync(devId, friendlyName, reason);
        }

        if (preview is null)
        {
            var unreachDialog = new ContentDialog
            {
                Title = "Service Unreachable",
                Content = "The USB action service endpoint is not reachable.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await unreachDialog.ShowAsync();
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Block Denied",
                Content = preview.Message,
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Target Device: {p.DeviceId} ({(string.IsNullOrWhiteSpace(p.FriendlyName) ? "Unknown" : p.FriendlyName)})\n\n" +
                          $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Are you sure you want to block and disable this USB device?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm USB Device Block",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "Block Device",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary && p.ConsentToken is not null)
        {
            SetBusy(true, $"Blocking USB device {p.DeviceId}...");
            var outcome = await client.BlockDeviceAsync(p.DeviceId!, p.ConsentToken, p.FriendlyName, reason);
            SetBusy(false, "");

            var outcomeDialog = new ContentDialog
            {
                Title = outcome?.Accepted == true ? "USB Device Blocked" : "Block Failed",
                Content = outcome?.Message ?? "No response received from action service.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await outcomeDialog.ShowAsync();
        }
    }

    private async void IsolateHost_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var durationBox = new TextBox { Text = "30", Width = 80, HorizontalAlignment = HorizontalAlignment.Left };
        var lockBox = new CheckBox { Content = "Lock Windows session immediately (user32.dll)", IsChecked = false };
        var reasonBox = new TextBox { Text = "Remediation incident containment", PlaceholderText = "Reason for host isolation" };

        var inputStack = new StackPanel { Spacing = 10 };
        inputStack.Children.Add(new TextBlock { Text = "Emergency Host Network Isolation (DN-008 Phase 5)", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        inputStack.Children.Add(new TextBlock { Text = "Windows Firewall will block all inbound and outbound non-loopback packets.\nLocal loopback (127.0.0.1, ::1) is preserved for local Downpour IPC.\nIsolation MUST auto-expire (5 to 1440 minutes). Permanent isolation is strictly prohibited.", TextWrapping = TextWrapping.Wrap, Foreground = SecondaryBrush(), FontSize = 12 });
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
            XamlRoot = this.XamlRoot
        };

        if (await requestDialog.ShowAsync() != ContentDialogResult.Primary) return;

        if (!int.TryParse(durationBox.Text.Trim(), out int durationMinutes) || durationMinutes < 5 || durationMinutes > 1440)
        {
            var invalidDialog = new ContentDialog
            {
                Title = "Invalid Duration",
                Content = new TextBlock { Text = "Duration must be an integer between 5 and 1440 minutes (24 hours). Permanent isolation is strictly prohibited." },
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await invalidDialog.ShowAsync();
            return;
        }

        bool lockWorkstation = lockBox.IsChecked == true;
        string reason = string.IsNullOrWhiteSpace(reasonBox.Text) ? "Remediation incident containment" : reasonBox.Text.Trim();

        SetBusy(true, "Requesting isolation preview...");
        var preview = await _isolationClient.PreviewIsolateAsync(durationMinutes, lockWorkstation, reason);
        SetBusy(false, "");

        if (preview is null)
        {
            var unreachDialog = new ContentDialog
            {
                Title = "Service Unreachable",
                Content = new TextBlock { Text = "The Downpour sensor service did not respond. Host isolation requires the elevated background service." },
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await unreachDialog.ShowAsync();
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Isolation Denied",
                Content = new TextBlock { Text = preview.Message },
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
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
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() != ContentDialogResult.Primary || p.ConsentToken is null) return;

        SetBusy(true, "Engaging host isolation...");
        var outcome = await _isolationClient.IsolateAsync(p.ConsentToken, p.DurationMinutes, p.LockWorkstation, reason);
        SetBusy(false, "");

        var outcomeDialog = new ContentDialog
        {
            Title = outcome?.Accepted == true ? "Host Isolation Engaged" : "Isolation Failed",
            Content = new TextBlock
            {
                Text = outcome?.Accepted == true
                    ? $"Host network is now isolated until {outcome.ActiveUntilUtc:HH:mm:ss} UTC.\n\nAll non-loopback inbound and outbound packets are dropped.\nLocal loopback (127.0.0.1, ::1) is preserved for Downpour IPC.\n\nRules: {string.Join(", ", outcome.RulesCreated ?? [])}"
                    : (outcome?.Message ?? "Isolation failed."),
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "OK",
            XamlRoot = this.XamlRoot
        };
        await outcomeDialog.ShowAsync();
        await RefreshAsync();
    }

    private async void ReleaseIsolation_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true, "Requesting release preview...");
        var preview = await _isolationClient.PreviewReleaseAsync("Remediation operator release");
        SetBusy(false, "");

        if (preview is null)
        {
            var unreachDialog = new ContentDialog
            {
                Title = "Service Unreachable",
                Content = new TextBlock { Text = "The sensor service did not respond." },
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await unreachDialog.ShowAsync();
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Release Denied",
                Content = new TextBlock { Text = preview.Message },
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
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
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() != ContentDialogResult.Primary || p.ConsentToken is null) return;

        SetBusy(true, "Releasing host isolation...");
        var outcome = await _isolationClient.ReleaseAsync(p.ConsentToken, "Remediation operator release");
        SetBusy(false, "");

        var outcomeDialog = new ContentDialog
        {
            Title = outcome?.Accepted == true ? "Network Restored" : "Release Failed",
            Content = new TextBlock
            {
                Text = outcome?.Accepted == true
                    ? "Host isolation firewall rules removed and timer cancelled. Normal network connectivity restored."
                    : (outcome?.Message ?? "Failed to release isolation."),
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "OK",
            XamlRoot = this.XamlRoot
        };
        await outcomeDialog.ShowAsync();
        await RefreshAsync();
    }

    private void SetBusy(bool busy, string status)
    {
        _busy = busy;
        Busy.IsActive = busy;
        RefreshButton.IsEnabled = !busy;
        if (busy)
        {
            QuarantineButton.IsEnabled = false;
            TerminateProcessButton.IsEnabled = false;
            BlockIpButton.IsEnabled = false;
            BlockUsbDeviceButton.IsEnabled = false;
            IsolateHostButton.IsEnabled = false;
            ReleaseIsolationButton.IsEnabled = false;
        }
        else
        {
            QuarantineButton.IsEnabled = true;
            TerminateProcessButton.IsEnabled = true;
            BlockIpButton.IsEnabled = true;
            BlockUsbDeviceButton.IsEnabled = true;
            IsolateHostButton.IsEnabled = true;
            ReleaseIsolationButton.IsEnabled = true;
        }
        if (status.Length > 0 || busy) StatusText.Text = status;
    }

    private static TextBlock Secondary(string text) =>
        new() { Text = text, FontSize = 12, TextWrapping = TextWrapping.Wrap, Foreground = SecondaryBrush() };

    private static Brush SecondaryBrush() => (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} bytes",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes / (1024.0 * 1024):0.#} MB",
    };
}
