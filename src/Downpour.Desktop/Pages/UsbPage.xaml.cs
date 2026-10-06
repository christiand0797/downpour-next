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
    private bool _requestInFlight;

    public ObservableCollection<UsbFindingRow> Findings { get; } = [];
    public ObservableCollection<UsbDeviceRow> ConnectedDevices { get; } = [];
    public ObservableCollection<UsbHistoryRow> History { get; } = [];

    public UsbPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        RefreshButton.IsEnabled = false;
        StatusHeadline.Text = "Checking USB device posture";

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

            foreach (var finding in snapshot.Findings.OrderBy(f => SeverityRank(f.Severity)))
                Findings.Add(new UsbFindingRow(finding));

            foreach (var dev in snapshot.ConnectedDevices)
                ConnectedDevices.Add(new UsbDeviceRow(dev));

            foreach (var hist in snapshot.History)
                History.Add(new UsbHistoryRow(hist));

            EmptyFindingsState.Visibility = Findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyDevicesState.Visibility = ConnectedDevices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyHistoryState.Visibility = History.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

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
        }
    }

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4
    };
}

public sealed class UsbFindingRow(UsbFinding finding)
{
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
    public string DriveLetter => dev.DriveLetter;
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
    public string FriendlyName => string.IsNullOrWhiteSpace(entry.FriendlyName) ? entry.DeviceId : entry.FriendlyName;
    public string SerialNumber => entry.SerialNumber;
    public string DeviceDetails => string.IsNullOrWhiteSpace(entry.Vendor) ? entry.HardwareId : $"{entry.Vendor} / {entry.Product} (HW: {entry.HardwareId})";
}
