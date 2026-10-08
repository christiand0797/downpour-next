using System.Collections.ObjectModel;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour_Desktop.Pages;

public sealed partial class IoTPage : Page
{
    private readonly IoTDeviceScanner _scanner = new();
    private IoTSnapshot? _snapshot;
    private readonly List<IoTDevice> _allDevices = [];
    private readonly ObservableCollection<DeviceRow> _deviceRows = [];

    public IoTPage()
    {
        InitializeComponent();
        EntityDetails.Attach(DevicesList, item => item is DeviceRow d ? DetailDescriptions.IoT(d.Device) : null, clickOpensDetails: false);
        DevicesList.ItemsSource = _deviceRows;
        DevicesList.SelectionChanged += DevicesList_SelectionChanged;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        RunScan();
    }

    private void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        RunScan();
    }

    private async void RunScan()
    {
        ScanButton.IsEnabled = false;
        StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 30, 58, 138));
        StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 96, 165, 250));
        StatusBadgeText.Text = "SCANNING";
        AppendLog("Beginning local subnet ARP discovery and vendor fingerprinting...");

        try
        {
            var snapshot = await Task.Run(() => _scanner.ScanLocalNetwork());
            _snapshot = snapshot;
            _allDevices.Clear();
            _allDevices.AddRange(snapshot.Devices);

            ApplyFilter();
            UpdateMetrics(snapshot.Summary);

            if (snapshot.Summary.BotnetThreats > 0)
            {
                StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 127, 29, 29));
                StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
                StatusBadgeText.Text = "THREATS DETECTED";
            }
            else
            {
                StatusBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59));
                StatusBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
                StatusBadgeText.Text = "CLEAN";
            }

            AppendLog($"Scan complete: discovered {snapshot.Summary.TotalDevices} device(s), {snapshot.Summary.BotnetThreats} botnet flag(s).");
        }
        catch (Exception ex)
        {
            AppendLog($"Scan error: {ex.Message}");
            StatusBadgeText.Text = "ERROR";
        }
        finally
        {
            ScanButton.IsEnabled = true;
        }
    }

    private void UpdateMetrics(IoTSummary summary)
    {
        MetricTotalDevices.Text = summary.TotalDevices.ToString();
        MetricBotnetThreats.Text = summary.BotnetThreats.ToString();
        MetricSmartHome.Text = summary.SmartHomeDevices.ToString();
        MetricCameras.Text = summary.Cameras.ToString();
    }

    private void DevicesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DevicesList.SelectedItem is DeviceRow row)
        {
            DisplayDeviceDetails(row.Device);
        }
    }

    private void DisplayDeviceDetails(IoTDevice dev)
    {
        SelectedDeviceHeader.Text = $"{dev.IpAddress} ({dev.HostName})";
        SelectedDeviceVendor.Text = $"Vendor: {dev.Vendor}";
        SelectedDeviceMac.Text = $"MAC: {dev.MacAddress}";
        SelectedDeviceCategory.Text = $"Category: {dev.DeviceCategory}";
        SelectedDeviceThreat.Text = $"Threat Level: {dev.ThreatLevel}";
        SelectedDeviceScore.Text = $"Risk Score: {dev.RiskScore} / 100";

        if (dev.ThreatLevel is "CRITICAL" or "HIGH")
        {
            SelectedDeviceThreat.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
            SelectedDeviceAction.Text = "High-risk device exhibiting botnet or exposure indicators. Isolate device via router ACL or dedicated IoT VLAN.";
            SelectedDeviceAction.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
        }
        else if (dev.ThreatLevel == "MEDIUM")
        {
            SelectedDeviceThreat.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 251, 191, 36));
            SelectedDeviceAction.Text = "Medium-risk device with open management services. Review credentials and update firmware.";
            SelectedDeviceAction.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 251, 191, 36));
        }
        else
        {
            SelectedDeviceThreat.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
            SelectedDeviceAction.Text = "Standard network device. No isolation needed.";
            SelectedDeviceAction.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 156, 163, 175));
        }

        if (dev.IdentifiedServices.Count > 0)
        {
            SelectedDeviceServices.Text = string.Join("\n", dev.IdentifiedServices);
            SelectedDeviceServices.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 243, 244, 246));
        }
        else
        {
            SelectedDeviceServices.Text = "No open services probed yet (click 'Probe Selected').";
            SelectedDeviceServices.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 156, 163, 175));
        }

        if (dev.BotnetIndicators.Count > 0)
        {
            SelectedDeviceBotnets.Text = string.Join("\n", dev.BotnetIndicators);
            SelectedDeviceBotnets.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
        }
        else
        {
            SelectedDeviceBotnets.Text = "No botnet signatures detected.";
            SelectedDeviceBotnets.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }
    }

    private async void ProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesList.SelectedItem is not DeviceRow row)
        {
            AppendLog("Please select a device from the list to probe.");
            return;
        }

        ProbeButton.IsEnabled = false;
        AppendLog($"Probing IoT & botnet ports on {row.Device.IpAddress}...");

        try
        {
            var updated = await _scanner.ProbeDeviceAsync(row.Device);

            // Update in device list
            var idx = _allDevices.FindIndex(d => d.IpAddress == updated.IpAddress);
            if (idx >= 0)
            {
                _allDevices[idx] = updated;
            }

            ApplyFilter();
            DisplayDeviceDetails(updated);

            AppendLog($"Probe completed for {updated.IpAddress}: {updated.OpenPorts.Count} open port(s), threat level: {updated.ThreatLevel}");
        }
        catch (Exception ex)
        {
            AppendLog($"Error probing device: {ex.Message}");
        }
        finally
        {
            ProbeButton.IsEnabled = true;
        }
    }

    private async void BlockButton_Click(object sender, RoutedEventArgs e)
    {
        var target = DevicesList.SelectedItem is DeviceRow row ? row.Device.IpAddress : "selected device";
        var dialog = new ContentDialog
        {
            Title = "IoT Device Blocking Guarded Action",
            Content = new TextBlock
            {
                Text = $"Blocking network communications with {target} via Windows Firewall or router ACL is guarded under the Downpour response policy (DN-008).\n\n" +
                       "In accordance with project security invariants, mutating host firewall policy requires an audited action broker, administrative elevation, and verified dry-run/rollback guarantees.\n\n" +
                       "Direct netsh invocation is disabled to ensure system safety and prevent unexpected network disruption.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "Acknowledge",
            XamlRoot = this.XamlRoot
        };

        AppendLog($"Block action for {target} intercepted: privileged action requires audited action broker (DN-008).");
        await dialog.ShowAsync();
    }

    private async void ExportReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_snapshot == null)
        {
            RunScan();
        }

        if (_snapshot == null) return;

        try
        {
            var report = IoTDeviceScanner.GenerateReport(_snapshot);
            var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
            var fileName = $"IoT_Security_Report_{timestamp}.md";

            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var filePath = Path.Combine(desktopDir, fileName);

            await File.WriteAllTextAsync(filePath, report);
            AppendLog($"IoT audit report exported to Desktop: {fileName}");

            var dialog = new ContentDialog
            {
                Title = "Report Exported",
                Content = new TextBlock
                {
                    Text = $"IoT Subnet Security Report saved successfully to:\n{filePath}",
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

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyFilter();
    }

    private void FilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? string.Empty;
        var filterIndex = FilterCombo?.SelectedIndex ?? 0;

        var filtered = _allDevices.Where(d =>
        {
            if (!string.IsNullOrEmpty(query))
            {
                var matches = d.IpAddress.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                              d.MacAddress.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                              d.Vendor.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                              d.DeviceCategory.Contains(query, StringComparison.OrdinalIgnoreCase);
                if (!matches) return false;
            }

            return filterIndex switch
            {
                1 => d.ThreatLevel is "CRITICAL" or "HIGH" or "MEDIUM" || d.BotnetIndicators.Count > 0,
                2 => d.DeviceCategory.Contains("Smart Home"),
                3 => d.DeviceCategory.Contains("Camera"),
                _ => true
            };
        });

        _deviceRows.Clear();
        foreach (var dev in filtered)
        {
            _deviceRows.Add(new DeviceRow(dev));
        }
    }

    private void AppendLog(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        LogTextBox.Text = $"[{timestamp}] {message}\n" + LogTextBox.Text;
    }
}

public sealed class DeviceRow(IoTDevice device)
{
    public IoTDevice Device => device;

    public string IpAddress => Device.IpAddress;
    public string VendorSummary => $"{Device.Vendor} ({Device.HostName})";
    public string MacSummary => $"MAC: {Device.MacAddress}";
    public string CategorySummary => Device.DeviceCategory;
    public string PortsSummary => Device.OpenPorts.Count > 0
        ? $"Ports: {string.Join(", ", Device.OpenPorts)}"
        : "Ports: Unprobed";

    public string ThreatText => Device.ThreatLevel;
    public Brush ThreatBackground => Device.ThreatLevel switch
    {
        "CRITICAL" => new SolidColorBrush(ColorHelper.FromArgb(255, 127, 29, 29)),
        "HIGH" => new SolidColorBrush(ColorHelper.FromArgb(255, 154, 52, 18)),
        "MEDIUM" => new SolidColorBrush(ColorHelper.FromArgb(255, 113, 63, 18)),
        "LOW" => new SolidColorBrush(ColorHelper.FromArgb(255, 30, 58, 138)),
        _ => new SolidColorBrush(ColorHelper.FromArgb(255, 6, 78, 59))
    };

    public Brush ThreatForeground => Device.ThreatLevel switch
    {
        "CRITICAL" => new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113)),
        "HIGH" => new SolidColorBrush(ColorHelper.FromArgb(255, 251, 146, 60)),
        "MEDIUM" => new SolidColorBrush(ColorHelper.FromArgb(255, 251, 191, 36)),
        "LOW" => new SolidColorBrush(ColorHelper.FromArgb(255, 96, 165, 250)),
        _ => new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153))
    };

    public string ScoreSummary => $"Score: {Device.RiskScore}";
    public string BotnetAlert => Device.BotnetIndicators.Count > 0 ? "[BOTNET ALERT]" : "";
}
