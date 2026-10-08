using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class UsbPage : Page
{
    private readonly UsbInventoryClient _client = new();
    private readonly UsbActionClient _actionClient = new();
    private bool _requestInFlight;
    private bool _usbStorageEnabled = true;

    public LiveCollection<UsbFindingRow> Findings { get; } = [];
    public LiveCollection<UsbDeviceRow> ConnectedDevices { get; } = [];
    public LiveCollection<UsbHistoryRow> History { get; } = [];

    private readonly TopBarsChart _spaceChart = new() { Title = "Drive space used", Subtitle = "Connected removable drives" };
    private readonly BreakdownChart _findingChart = new() { Title = "USB findings", Subtitle = "Autorun, suspicious files, new devices" };
    private readonly TopBarsChart _vendorChart = new() { Title = "Devices seen by maker", Subtitle = "USB storage devices this PC has ever recorded" };

    public UsbPage()
    {
        InitializeComponent();
        EntityDetails.Attach(FindingList, item => item is UsbFindingRow f ? DetailDescriptions.Finding("USB", f.Severity, f.Technique, f.Summary, f.Indicator) : null);
        EntityDetails.Attach(DriveList, item => item is UsbDeviceRow d ? DetailDescriptions.UsbDrive(d.Device) : null);
        EntityDetails.Attach(HistoryList, item => item is UsbHistoryRow h ? DetailDescriptions.UsbHistory(h.Entry) : null);
        Charts.Row(ChartRow, _spaceChart, _findingChart, _vendorChart);
        LiveRefresh.Attach(this, () => RefreshAsync(quiet: true));
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync(bool quiet = false)
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        if (!quiet) RefreshButton.IsEnabled = false;
        if (!quiet) ToggleUsbStorageButton.IsEnabled = false;
        if (!quiet) StatusHeadline.Text = "Checking USB device posture";

        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            Findings.Clear();
            ConnectedDevices.Clear();
            History.Clear();

            if (snapshot is null)
            {
                StatusHeadline.Text = "Downpour is running · USB sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted USB data is shown.";
                EmptyFindingsState.Visibility = Visibility.Visible;
                EmptyDevicesState.Visibility = Visibility.Visible;
                EmptyHistoryState.Visibility = Visibility.Visible;
                return;
            }

            App.MarkSensorServiceConnected();

            _usbStorageEnabled = snapshot.UsbStorageServiceEnabled;
            ToggleUsbStorageButton.Content = _usbStorageEnabled ? "Disable USB Mass Storage" : "Enable USB Mass Storage";

            foreach (var finding in snapshot.Findings.OrderBy(f => SeverityRank(f.Severity)))
                Findings.Add(new UsbFindingRow(finding));

            foreach (var dev in snapshot.ConnectedDevices)
                ConnectedDevices.Add(new UsbDeviceRow(dev));

            foreach (var hist in snapshot.History)
                History.Add(new UsbHistoryRow(hist));

            EmptyFindingsState.Visibility = Findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyDevicesState.Visibility = ConnectedDevices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyHistoryState.Visibility = History.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            _spaceChart.SetData(snapshot.ConnectedDevices.Where(d => d.TotalSizeBytes > 0)
                .Select(d => ($"{d.DriveLetter} {d.VolumeLabel}".Trim(), Math.Round(100.0 * (d.TotalSizeBytes - d.FreeSizeBytes) / d.TotalSizeBytes, 1))), "%",
                colorFor: used => used >= 90 ? HudPalette.Serious : null);
            _findingChart.SetData(snapshot.Findings.GroupBy(f => f.Severity, StringComparer.OrdinalIgnoreCase).Select(g => (g.Key, (double)g.Count())));
            _vendorChart.SetData(snapshot.History.GroupBy(h => string.IsNullOrWhiteSpace(h.Vendor) ? "(unknown)" : h.Vendor.Trim(), StringComparer.OrdinalIgnoreCase)
                .Select(g => (g.Key, (double)g.Count())), "", HudPalette.Categorical[1]);
            var findingCount = snapshot.Findings.Count;
            var devCount = snapshot.ConnectedDevices.Count;
            var svcState = snapshot.UsbStorageServiceEnabled ? "USB storage driver enabled" : "USB storage driver disabled";
            StatusHeadline.Text = findingCount == 0
                ? $"{svcState} · {devCount} removable drive{(devCount == 1 ? "" : "s")} connected · 0 findings"
                : $"{svcState} · {devCount} removable drive{(devCount == 1 ? "" : "s")} · {findingCount} finding{(findingCount == 1 ? "" : "s")}";

            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"Checked {captured:HH:mm:ss}. {snapshot.History.Count} devices in history.{warnings}";
        }
        finally
        {
            _requestInFlight = false;
            RefreshButton.IsEnabled = true;
            ToggleUsbStorageButton.IsEnabled = true;
        }
    }

    private async void ToggleUsbStorage_Click(object sender, RoutedEventArgs e)
    {
        var targetState = !_usbStorageEnabled;
        var actionWord = targetState ? "enable" : "disable";
        ToggleUsbStorageButton.IsEnabled = false;

        try
        {
            var preview = await _actionClient.PreviewSetUsbStorageAsync(targetState, $"User requested to {actionWord} USB mass storage driver.");
            if (preview is null)
            {
                await App.EnsureSensorServiceAsync();
                preview = await _actionClient.PreviewSetUsbStorageAsync(targetState, $"User requested to {actionWord} USB mass storage driver.");
            }

            if (preview is null)
            {
                await ShowDialogAsync("Service Unreachable", "The USB action service endpoint is not reachable.");
                return;
            }

            if (!preview.Accepted || preview.Preview is null)
            {
                await ShowDialogAsync("Action Denied", preview.Message);
                return;
            }

            var p = preview.Preview;
            var details = $"Operation: {(targetState ? "Enable USB Mass Storage (USBSTOR)" : "Disable USB Mass Storage (USBSTOR)")}\n\n" +
                          $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Are you sure you want to proceed?";

            if (await ConfirmAsync("Confirm USB Storage Policy Change", details, targetState ? "Enable" : "Disable") && p.ConsentToken is not null)
            {
                var outcome = await _actionClient.SetUsbStorageAsync(targetState, p.ConsentToken);
                await ShowDialogAsync(outcome?.Accepted == true ? "USB Storage Updated" : "Update Failed", outcome?.Message ?? "No response received.");
                await RefreshAsync();
            }
        }
        finally
        {
            ToggleUsbStorageButton.IsEnabled = true;
        }
    }

    private async void BlockDrive_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: UsbDeviceRow row }) return;

        if (row.PnpDeviceId is not { } devId)
        {
            await ShowDialogAsync("Device identity unknown", $"Windows did not report a USB storage device behind {row.DriveLetter}, so it cannot be blocked from here.");
            return;
        }
        var friendlyName = string.IsNullOrWhiteSpace(row.VolumeLabel) ? $"Removable Drive ({row.DriveLetter})" : row.VolumeLabel;

        var preview = await _actionClient.PreviewBlockDeviceAsync(devId, friendlyName, "Operator blocked drive instance from USB posture page.");
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await _actionClient.PreviewBlockDeviceAsync(devId, friendlyName, "Operator blocked drive instance from USB posture page.");
        }

        if (preview is null)
        {
            await ShowDialogAsync("Service Unreachable", "The USB action service endpoint is not reachable.");
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            await ShowDialogAsync("Block Denied", preview.Message);
            return;
        }

        var p = preview.Preview;
        var details = $"Target: {p.DeviceId} ({p.FriendlyName})\n\n" +
                      $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                      $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                      "Consent token minted (valid for 60 seconds). Are you sure you want to block and disable this device?";

        if (await ConfirmAsync("Confirm USB Device Block", details, "Block Device") && p.ConsentToken is not null)
        {
            var outcome = await _actionClient.BlockDeviceAsync(p.DeviceId!, p.ConsentToken, p.FriendlyName, "Operator confirmed block.");
            await ShowDialogAsync(outcome?.Accepted == true ? "Device Blocked" : "Block Failed", outcome?.Message ?? "No response received.");
            await RefreshAsync();
        }
    }

    private async void BlockHistoryDevice_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: UsbHistoryRow row }) return;

        var devId = row.DeviceId;
        var friendlyName = row.FriendlyName;

        var preview = await _actionClient.PreviewBlockDeviceAsync(devId, friendlyName, "Operator blocked USB device instance from history.");
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await _actionClient.PreviewBlockDeviceAsync(devId, friendlyName, "Operator blocked USB device instance from history.");
        }

        if (preview is null)
        {
            await ShowDialogAsync("Service Unreachable", "The USB action service endpoint is not reachable.");
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            await ShowDialogAsync("Block Denied", preview.Message);
            return;
        }

        var p = preview.Preview;
        var details = $"Target Device ID: {p.DeviceId}\n" +
                      $"Friendly Name: {p.FriendlyName}\n\n" +
                      $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                      $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                      "Consent token minted (valid for 60 seconds). Are you sure you want to block and disable this device?";

        if (await ConfirmAsync("Confirm USB Device Block", details, "Block Device") && p.ConsentToken is not null)
        {
            var outcome = await _actionClient.BlockDeviceAsync(p.DeviceId!, p.ConsentToken, p.FriendlyName, "Operator confirmed block.");
            await ShowDialogAsync(outcome?.Accepted == true ? "Device Blocked" : "Block Failed", outcome?.Message ?? "No response received.");
            await RefreshAsync();
        }
    }

    private async Task<bool> ConfirmAsync(string title, string body, string primaryButton)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new ScrollViewer { Content = new TextBlock { Text = body, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true }, MaxHeight = 360 },
            PrimaryButtonText = primaryButton,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async Task ShowDialogAsync(string title, string body)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new TextBlock { Text = body, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true },
            CloseButtonText = "OK",
            XamlRoot = XamlRoot,
        };
        await dialog.ShowAsync();
    }

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4
    };
}

public sealed class UsbFindingRow(UsbFinding finding)
{
    public UsbFinding Finding => finding;
    public string Severity => finding.Severity;
    public string Technique => finding.Technique;
    public string Summary => finding.Summary;
    public string Indicator => finding.Indicator;

    public SolidColorBrush SeverityForeground => new(finding.Severity switch
    {
        "CRITICAL" => Color.FromArgb(255, 255, 80, 80),
        "HIGH" => Color.FromArgb(255, 255, 120, 110),
        "MEDIUM" => Color.FromArgb(255, 255, 170, 90),
        _ => Color.FromArgb(255, 120, 230, 160)
    });

    public SolidColorBrush SeverityBackground => new(finding.Severity switch
    {
        "CRITICAL" => Color.FromArgb(56, 255, 60, 60),
        "HIGH" => Color.FromArgb(56, 240, 90, 70),
        "MEDIUM" => Color.FromArgb(48, 230, 150, 50),
        _ => Color.FromArgb(48, 60, 200, 120)
    });
}

public sealed class UsbDeviceRow(UsbConnectedDevice dev)
{
    public UsbConnectedDevice Device => dev;
    public string DriveLetter => dev.DriveLetter;
    public string? PnpDeviceId => dev.PnpDeviceId;
    public Microsoft.UI.Xaml.Visibility BlockVisibility => dev.PnpDeviceId is null ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;
    public string VolumeLabel => dev.VolumeLabel;
    public string FileSystem => dev.FileSystem;

    public string StorageInfo
    {
        get
        {
            var totalGb = dev.TotalSizeBytes / (1024.0 * 1024 * 1024);
            var freeGb = dev.FreeSizeBytes / (1024.0 * 1024 * 1024);
            return $"{freeGb:F1} GB free of {totalGb:F1} GB";
        }
    }

    public string AutorunLabel => dev.HasAutorun ? "AUTORUN DETECTED" : "No Autorun";
    public SolidColorBrush AutorunForeground => new(dev.HasAutorun ? Color.FromArgb(255, 255, 100, 90) : Color.FromArgb(255, 120, 230, 160));
    public SolidColorBrush AutorunBackground => new(dev.HasAutorun ? Color.FromArgb(56, 255, 60, 60) : Color.FromArgb(36, 60, 200, 120));

    public string SuspiciousLabel => dev.HasSuspiciousFiles ? "SUSPICIOUS ROOT FILES" : "Clean Root";
    public SolidColorBrush SuspiciousForeground => new(dev.HasSuspiciousFiles ? Color.FromArgb(255, 255, 170, 90) : Color.FromArgb(255, 120, 230, 160));
    public SolidColorBrush SuspiciousBackground => new(dev.HasSuspiciousFiles ? Color.FromArgb(48, 230, 150, 50) : Color.FromArgb(36, 60, 200, 120));
}

public sealed class UsbHistoryRow(UsbDeviceHistoryEntry entry)
{
    public UsbDeviceHistoryEntry Entry => entry;
    public string DeviceId => entry.DeviceId;
    public string FriendlyName => DisplayName(entry.FriendlyName, entry.DeviceId);

    /// <summary>Only USB storage instances can be blocked (the service refuses hubs, controllers, and input devices).</summary>
    public Microsoft.UI.Xaml.Visibility BlockVisibility =>
        entry.DeviceId.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase) ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;

    /// <summary>
    /// Registry device descriptions are often indirect strings such as
    /// "@dc1-controller.inf,%usbid_045e&amp;pid_02ea.devicedesc%;Xbox One Controller"; the readable name follows the last ';'.
    /// </summary>
    internal static string DisplayName(string? friendlyName, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(friendlyName)) return deviceId;
        var name = friendlyName.Trim();
        if (name.StartsWith('@'))
        {
            var separator = name.LastIndexOf(';');
            name = separator >= 0 && separator < name.Length - 1 ? name[(separator + 1)..].Trim() : deviceId;
        }
        return name.Length == 0 ? deviceId : name;
    }
    public string SerialNumber => entry.SerialNumber;
    public string DeviceDetails => string.IsNullOrWhiteSpace(entry.Vendor) ? entry.HardwareId : $"{entry.Vendor} / {entry.Product} (HW: {entry.HardwareId})";
}
