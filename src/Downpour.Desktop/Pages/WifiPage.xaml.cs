using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class WifiPage : Page
{
    private readonly WirelessInventoryClient _client = new();
    private bool _requestInFlight;

    public ObservableCollection<WirelessFindingRow> Findings { get; } = [];
    public ObservableCollection<WifiNetworkRow> Networks { get; } = [];
    public ObservableCollection<BluetoothDeviceRow> BluetoothDevices { get; } = [];

    public WifiPage() => InitializeComponent();

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
        StatusHeadline.Text = "Checking wireless posture";

        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            Findings.Clear();
            Networks.Clear();
            BluetoothDevices.Clear();

            if (snapshot is null)
            {
                StatusHeadline.Text = "Downpour is running · wireless sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted wireless data is shown.";
                EmptyFindingsState.Visibility = Visibility.Visible;
                EmptyNetworksState.Visibility = Visibility.Visible;
                EmptyBtState.Visibility = Visibility.Visible;
                return;
            }

            App.MarkSensorServiceConnected();

            foreach (var finding in snapshot.Findings.OrderBy(f => SeverityRank(f.Severity)))
                Findings.Add(new WirelessFindingRow(finding));

            foreach (var net in snapshot.WifiNetworks.OrderByDescending(n => n.IsConnected).ThenByDescending(n => n.SignalPercent))
                Networks.Add(new WifiNetworkRow(net));

            foreach (var bt in snapshot.BluetoothDevices)
                BluetoothDevices.Add(new BluetoothDeviceRow(bt));

            EmptyFindingsState.Visibility = Findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyNetworksState.Visibility = Networks.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyBtState.Visibility = BluetoothDevices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            var findingCount = snapshot.Findings.Count;
            var netCount = snapshot.WifiNetworks.Count;
            var btCount = snapshot.BluetoothDevices.Count;

            var wifiStatus = snapshot.ConnectedSsid is not null
                ? $"Connected to '{snapshot.ConnectedSsid}'"
                : snapshot.WifiAdapterAvailable ? "Wi-Fi adapter ready (not connected)" : "Wi-Fi adapter unavailable/off";
            var btStatus = snapshot.BluetoothAdapterEnabled ? $"Bluetooth enabled ({btCount} paired)" : "Bluetooth disabled";

            StatusHeadline.Text = findingCount == 0
                ? $"{wifiStatus} · {netCount} networks visible · 0 findings"
                : $"{wifiStatus} · {netCount} networks · {findingCount} finding{(findingCount == 1 ? "" : "s")}";

            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"Checked {captured:HH:mm:ss}. {btStatus}.{warnings}";
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

public sealed class WirelessFindingRow(WirelessFinding finding)
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

public sealed class WifiNetworkRow(WifiNetworkEntry net)
{
    public string SsidDisplay => string.IsNullOrWhiteSpace(net.Ssid) ? "(Hidden Network)" : net.Ssid;
    public string Details => $"BSSID: {net.Bssid} · Ch {net.Channel} · {net.Cipher} · {net.NetworkType}";
    public string Authentication => net.Authentication;
    public string SignalDisplay => $"{net.SignalPercent}%";
    public Visibility ConnectedVisibility => net.IsConnected ? Visibility.Visible : Visibility.Collapsed;

    public SolidColorBrush SignalForeground => new(net.SignalPercent switch
    {
        >= 70 => Color.FromArgb(255, 120, 230, 160),
        >= 40 => Color.FromArgb(255, 255, 214, 102),
        _ => Color.FromArgb(255, 255, 120, 110)
    });

    public SolidColorBrush SignalBackground => new(net.SignalPercent switch
    {
        >= 70 => Color.FromArgb(36, 60, 200, 120),
        >= 40 => Color.FromArgb(36, 230, 190, 60),
        _ => Color.FromArgb(36, 240, 90, 70)
    });

    public SolidColorBrush AuthForeground => new(IsWeak(net.Authentication)
        ? Color.FromArgb(255, 255, 100, 90)
        : Color.FromArgb(255, 120, 230, 160));

    public SolidColorBrush AuthBackground => new(IsWeak(net.Authentication)
        ? Color.FromArgb(56, 255, 60, 60)
        : Color.FromArgb(36, 60, 200, 120));

    private static bool IsWeak(string auth) =>
        auth.Equals("Open", StringComparison.OrdinalIgnoreCase) ||
        auth.Equals("None", StringComparison.OrdinalIgnoreCase) ||
        auth.Equals("WEP", StringComparison.OrdinalIgnoreCase) ||
        auth.Equals("Shared", StringComparison.OrdinalIgnoreCase);
}

public sealed class BluetoothDeviceRow(BluetoothDeviceEntry dev)
{
    public string Name => dev.Name;
    public string Address => dev.Address;
    public Visibility SuspiciousVisibility => dev.IsSuspicious ? Visibility.Visible : Visibility.Collapsed;
}
