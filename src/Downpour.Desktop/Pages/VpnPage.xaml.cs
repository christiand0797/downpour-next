using System.Collections.ObjectModel;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour_Desktop.Pages;

public sealed partial class VpnPage : Page
{
    private readonly VpnPostureInspector _inspector = new();
    private readonly List<VpnProfileSummary> _importedProfiles = [];
    private VpnPostureSnapshot? _snapshot;

    private readonly ObservableCollection<AdapterRow> _adapterRows = [];
    private readonly ObservableCollection<ConnectivityRow> _connectivityRows = [];
    private readonly ObservableCollection<ProfileRow> _profileRows = [];

    public VpnPage()
    {
        InitializeComponent();
        AdaptersList.ItemsSource = _adapterRows;
        ConnectivityList.ItemsSource = _connectivityRows;
        ProfilesList.ItemsSource = _profileRows;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        RefreshPosture();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshPosture();
    }

    private void RefreshPosture()
    {
        try
        {
            _snapshot = _inspector.InspectPosture(_importedProfiles);
            UpdateUi(_snapshot);
            AppendLog($"Posture refreshed. VPN: {(_snapshot.IsVpnConnected ? "Connected (" + _snapshot.PrimaryProvider + ")" : "Disconnected")}, DNS: {_snapshot.DnsLeak.Status}");
        }
        catch (Exception ex)
        {
            AppendLog($"Error refreshing VPN posture: {ex.Message}");
        }
    }

    private void UpdateUi(VpnPostureSnapshot snapshot)
    {
        // Badges
        if (snapshot.IsVpnConnected)
        {
            VpnStatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59));
            VpnStatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
            VpnStatusBadgeText.Text = $"CONNECTED ({snapshot.PrimaryProvider.ToUpperInvariant()})";
            MetricVpnStatus.Text = "Connected";
            MetricVpnStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }
        else
        {
            VpnStatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 30, 41, 59));
            VpnStatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 148, 163, 184));
            VpnStatusBadgeText.Text = "DISCONNECTED";
            MetricVpnStatus.Text = "Disconnected";
            MetricVpnStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 148, 163, 184));
        }

        MetricProvider.Text = $"Provider: {snapshot.PrimaryProvider}";

        // DNS Leak
        if (snapshot.DnsLeak.HasLeakRisk)
        {
            DnsLeakBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 127, 29, 29));
            DnsLeakBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
            DnsLeakBadgeText.Text = "DNS LEAK RISK";
            MetricDnsStatus.Text = "Split-Tunnel Risk";
            MetricDnsStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
        }
        else
        {
            DnsLeakBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59));
            DnsLeakBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
            DnsLeakBadgeText.Text = "DNS PROTECTED";
            MetricDnsStatus.Text = snapshot.IsVpnConnected ? "Tunnel DNS Only" : "Physical DNS";
            MetricDnsStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }

        MetricDnsServerCount.Text = $"{snapshot.DnsLeak.VpnDnsServers.Count} Tunnel / {snapshot.DnsLeak.PhysicalDnsServers.Count} Physical";
        DnsLeakDetailText.Text = snapshot.DnsLeak.Status;
        DnsFindingsList.ItemsSource = snapshot.DnsLeak.Findings;

        // Adapters
        MetricAdapterCount.Text = snapshot.Interfaces.Count.ToString();
        var vpnCount = snapshot.Interfaces.Count(i => i.IsVpn && i.OperationalStatus == "Up");
        MetricVpnAdapters.Text = $"{vpnCount} Active VPN Tunnel(s)";

        _adapterRows.Clear();
        foreach (var iface in snapshot.Interfaces)
        {
            _adapterRows.Add(new AdapterRow(iface));
        }

        // Profiles
        _profileRows.Clear();
        foreach (var prof in snapshot.Profiles)
        {
            _profileRows.Add(new ProfileRow(prof));
        }
    }

    private async void TestConnectivityButton_Click(object sender, RoutedEventArgs e)
    {
        TestConnectivityButton.IsEnabled = false;
        MetricEgressStatus.Text = "Testing...";
        AppendLog("Beginning TCP port 443 egress connectivity probes (non-ICMP)...");

        try
        {
            var results = await _inspector.TestConnectivityAsync();
            _connectivityRows.Clear();
            int totalLatency = 0;
            int count = 0;

            foreach (var res in results)
            {
                _connectivityRows.Add(new ConnectivityRow(res));
                if (res.Reachable)
                {
                    totalLatency += res.LatencyMs;
                    count++;
                }
                AppendLog($"Probe {res.Target}: {(res.Reachable ? $"[OK] {res.LatencyMs}ms" : "[FAIL]")}");
            }

            if (count > 0)
            {
                MetricEgressStatus.Text = "Operational";
                MetricEgressStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
                MetricLatencyAvg.Text = $"Avg Latency: {totalLatency / count} ms";
            }
            else
            {
                MetricEgressStatus.Text = "Degraded";
                MetricEgressStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
                MetricLatencyAvg.Text = "No probes succeeded";
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Connectivity probe failure: {ex.Message}");
            MetricEgressStatus.Text = "Error";
        }
        finally
        {
            TestConnectivityButton.IsEnabled = true;
        }
    }

    private async void ImportProfileButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);

            picker.ViewMode = PickerViewMode.List;
            picker.SuggestedStartLocation = PickerLocationId.Downloads;
            picker.FileTypeFilter.Add(".ovpn");
            picker.FileTypeFilter.Add(".conf");
            picker.FileTypeFilter.Add(".txt");

            var file = await picker.PickSingleFileAsync();
            if (file != null)
            {
                var content = await Windows.Storage.FileIO.ReadTextAsync(file);
                var profile = VpnPostureInspector.ParseOvpnProfile(content, file.Name);
                _importedProfiles.Add(profile);
                AppendLog($"Imported VPN profile: {profile.Name} ({profile.RemoteHost}:{profile.RemotePort ?? 1194})");
                RefreshPosture();
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Error importing profile: {ex.Message}");
        }
    }

    private async void KillSwitchButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ContentDialog
        {
            Title = "VPN Kill-Switch Guarded Action",
            Content = new TextBlock
            {
                Text = "Windows Firewall kill-switch configuration is guarded under the Downpour response policy (DN-008).\n\n" +
                       "In accordance with project security invariants, mutating host firewall policy requires an audited action broker, administrative elevation, and verified dry-run/rollback guarantees.\n\n" +
                       "Direct netsh invocation is disabled to ensure system safety and prevent unexpected network isolation.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "Acknowledge",
            XamlRoot = this.XamlRoot
        };

        AppendLog("Kill-Switch action intercepted: privileged action requires audited action broker (DN-008).");
        await dialog.ShowAsync();
    }

    private async void ExportReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_snapshot == null)
        {
            RefreshPosture();
        }

        if (_snapshot == null) return;

        try
        {
            var report = VpnPostureInspector.GenerateReport(_snapshot);
            var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
            var fileName = $"Vpn_Posture_Report_{timestamp}.md";

            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var filePath = Path.Combine(desktopDir, fileName);

            await File.WriteAllTextAsync(filePath, report);
            AppendLog($"VPN audit report exported to Desktop: {fileName}");

            var dialog = new ContentDialog
            {
                Title = "Report Exported",
                Content = new TextBlock
                {
                    Text = $"VPN & Tunnel audit report saved successfully to:\n{filePath}",
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await dialog.ShowAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"Report export error: {ex.Message}");
        }
    }

    private void AppendLog(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        LogTextBox.Text = $"[{timestamp}] {message}\n" + LogTextBox.Text;
    }
}

public sealed class AdapterRow(VpnInterfaceInfo iface)
{
    public string Name => iface.Name;
    public string Description => iface.Description;

    public string BadgeText => iface.IsVpn ? $"VPN ({iface.DetectedProvider})" : "PHYSICAL";
    public Brush BadgeBackground => iface.IsVpn
        ? new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59))
        : new SolidColorBrush(ColorHelper.FromArgb(255, 30, 41, 59));
    public Brush BadgeForeground => iface.IsVpn
        ? new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153))
        : new SolidColorBrush(ColorHelper.FromArgb(255, 148, 163, 184));

    public string IpSummary => iface.IpAddresses.Count > 0
        ? $"IP: {string.Join(", ", iface.IpAddresses.Take(2))}"
        : "IP: Unassigned";

    public string DnsSummary => iface.DnsServers.Count > 0
        ? $"DNS: {string.Join(", ", iface.DnsServers.Take(2))}"
        : "DNS: None";

    public string GatewaySummary => !string.IsNullOrEmpty(iface.Gateway)
        ? $"GW: {iface.Gateway}"
        : "GW: None";

    public string StatusSummary => iface.OperationalStatus.ToUpperInvariant();
    public Brush StatusForeground => iface.OperationalStatus.Equals("Up", StringComparison.OrdinalIgnoreCase)
        ? new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153))
        : new SolidColorBrush(ColorHelper.FromArgb(255, 156, 163, 175));

    public string TypeSummary => iface.InterfaceType;
}

public sealed class ConnectivityRow(ConnectivityTestResult result)
{
    public string Target => result.Target;
    public string Details => result.Details;

    public string StatusText => result.Reachable ? $"[OK] {result.LatencyMs}ms" : "[UNREACHABLE]";
    public Brush StatusBackground => result.Reachable
        ? new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59))
        : new SolidColorBrush(ColorHelper.FromArgb(255, 127, 29, 29));
    public Brush StatusForeground => result.Reachable
        ? new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153))
        : new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
}

public sealed class ProfileRow(VpnProfileSummary profile)
{
    public string Name => profile.Name;
    public string EndpointSummary => $"{profile.RemoteHost}:{(profile.RemotePort?.ToString() ?? "Default")}";
    public string Protocol => profile.Protocol;
    public string Source => profile.Source;
}
