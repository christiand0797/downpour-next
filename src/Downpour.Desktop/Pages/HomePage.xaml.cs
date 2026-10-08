using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using Microsoft.UI.Text;
using Windows.Foundation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class HomePage : Page
{
    private readonly DispatcherQueueTimer _snapshotTimer;
    private readonly SystemSnapshotClient _snapshotClient = new();
    private readonly Queue<ResourceSample> _history = new();
    private bool _snapshotRequestInFlight;
    private bool _updateRequestInFlight;
    private bool _securityRequestInFlight;
    private DateTimeOffset _hardeningCheckedAt = DateTimeOffset.MinValue;
    private readonly SecurityAlertClient _alertClient = new();
    private readonly BlossomScene _blossom = new();
    private readonly HardeningPostureClient _hardeningClient = new();
    private readonly SensorSettingsClient _settingsClient = new();
    private DateTimeOffset _settingsCheckedAt = DateTimeOffset.MinValue;
    private CircularGauge? _cpuGauge;
    private CircularGauge? _memoryGauge;
    private ChartGrid? _resourceGrid;
    private ChartLineRenderer? _cpuSeries;
    private ChartLineRenderer? _memorySeries;

    public ObservableCollection<DashboardProcessRow> Processes { get; } = [];

    public HomePage()
    {
        InitializeComponent();
        SakuraLayer.Content = _blossom;
        _blossom.Attach(HomeContent, BlossomBand, CatPerch);
        _cpuGauge = new CircularGauge("CPU", Color.FromArgb(255, 74, 220, 243));
        _memoryGauge = new CircularGauge("MEMORY", Color.FromArgb(255, 178, 121, 248));
        GaugeHost.Children.Add(_cpuGauge);
        GaugeHost.Children.Add(_memoryGauge);

        _snapshotTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _snapshotTimer.Interval = TimeSpan.FromSeconds(1);
        _snapshotTimer.IsRepeating = true;
        _snapshotTimer.Tick += async (_, _) => { await RefreshSnapshotAsync(); await RefreshSecurityAsync(); };
        _snapshotTimer.Start();
        _ = RefreshSnapshotAsync();
        _ = RefreshSecurityAsync();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        StormModeController.ModeChanged += UpdateStormModeButton;
        UpdateStormModeButton(StormModeController.CurrentMode);
        if (!_snapshotTimer.IsRunning) _snapshotTimer.Start();
        _ = RefreshSnapshotAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        StormModeController.ModeChanged -= UpdateStormModeButton;
        _snapshotTimer.Stop();
        base.OnNavigatedFrom(e);
    }

    private void StormModeButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => StormModeController.Cycle();

    private async void UpdateButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (_updateRequestInFlight) return;
        var restarting = false;
        _updateRequestInFlight = true;
        UpdateButton.IsEnabled = false;
        UpdateButton.Content = "Checking updates…";
        try
        {
            var progress = new Progress<string>(message => UpdateButton.Content = message);
            var result = await PortableUpdateInstaller.CheckAndStageAsync(progress);
            UpdateButton.Content = result.Updated ? "Restarting to update…" : "⟳  Update Downpour";
            ToolTipService.SetToolTip(UpdateButton, result.Message);
            if (result.Updated)
            {
                restarting = true;
                App.CloseMainWindow();
            }
        }
        catch (Exception exception)
        {
            UpdateButton.Content = "⟳  Update Downpour";
            var detail = exception.Message.Length > 220 ? exception.Message[..220] : exception.Message;
            ToolTipService.SetToolTip(UpdateButton, $"Update did not complete: {detail}");
            SensorDescription.Text = $"Update did not complete: {detail}";
        }
        finally
        {
            _updateRequestInFlight = false;
            if (!restarting) UpdateButton.IsEnabled = true;
        }
    }

    private void UpdateStormModeButton(int mode)
    {
        if (DispatcherQueue.HasThreadAccess)
        {
            StormModeButton.Content = $"⛈  {StormModeController.Modes[mode]} · {(StormModeController.IsManual ? "MANUAL" : "AUTO")}";
            return;
        }
        _ = DispatcherQueue.TryEnqueue(() => StormModeButton.Content = $"⛈  {StormModeController.Modes[mode]} · {(StormModeController.IsManual ? "MANUAL" : "AUTO")}");
    }

    /// <summary>
    /// Security status from data the service already collects: open CRITICAL/HIGH or verified alerts (Threats), the
    /// Security Center antivirus check, and hardening findings. Posture is re-read at most once a minute.
    /// </summary>
    /// <summary>Response-action switches (every 10 s) and the route catalog, so the strip never shows stale claims.</summary>
    private async Task RefreshFooterAsync()
    {
        if (MigrationStatusText.Text.Length == 0)
        {
            try
            {
                var routes = CapabilityRegistry.Load(System.IO.Path.Combine(AppContext.BaseDirectory, "capabilities.json"));
                var complete = routes.Count(r => !r.Status.Equals("in-progress", StringComparison.OrdinalIgnoreCase));
                MigrationStatusText.Text = $"{routes.Count} routes · {complete} complete · {routes.Count - complete} in progress";
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                MigrationStatusText.Text = "Route catalog unavailable";
            }
        }
        if (DateTimeOffset.UtcNow - _settingsCheckedAt < TimeSpan.FromSeconds(10)) return;
        _settingsCheckedAt = DateTimeOffset.UtcNow;
        var response = await _settingsClient.GetAsync();
        if (response?.Settings is not { } settings)
        {
            ActionsStatusText.Text = "Unknown · sensor service offline";
            return;
        }
        var enabled = new[]
        {
            (settings.QuarantineActions, "quarantine"), (settings.ProcessTerminationActions, "process"), (settings.FirewallActions, "firewall"),
            (settings.UsbActions, "USB"), (settings.HostIsolationActions, "isolation"),
        }.Where(a => a.Item1).Select(a => a.Item2).ToArray();
        ActionsStatusText.Text = enabled.Length == 0
            ? "All switched off in Settings · observe only"
            : $"Confirm to act · {string.Join(", ", enabled)}";
    }

    private async Task RefreshSecurityAsync()
    {
        if (_securityRequestInFlight) return;
        _securityRequestInFlight = true;
        try
        {
            var alerts = await _alertClient.TryGetSnapshotAsync();
            EngineStatusText.Text = alerts is null
                ? "Sensor service offline · no counts shown"
                : $"Running · {alerts.Alerts.Count:N0} alerts from {alerts.Alerts.Select(a => a.LogName).Distinct().Count():N0} sources";
            await RefreshFooterAsync();
            if (alerts is null)
            {
                ThreatsMetricValue.Text = "—";
                ThreatsMetricDetail.Text = "Alert store unavailable while the sensor service is offline";
            }
            else
            {
                var open = alerts.Alerts.Where(a => a.State is "Open" or "Acknowledged").ToArray();
                var threats = open.Count(SecurityFindingCatalog.IsThreat);
                ThreatsMetricValue.Text = threats.ToString("N0");
                _blossom.SetThreats(threats);
                ThreatsMetricDetail.Text = threats == 0
                    ? $"No open threats · {open.Length - threats:N0} possible threats awaiting review"
                    : $"{open.Count(a => a.Severity == "CRITICAL"):N0} critical · {open.Length - threats:N0} possible threats · open Triage to review";
            }

            if (DateTimeOffset.UtcNow - _hardeningCheckedAt < TimeSpan.FromMinutes(1)) return;
            var posture = await _hardeningClient.TryGetSnapshotAsync();
            if (posture is null)
            {
                AntivirusMetricValue.Text = "—";
                AntivirusMetricDetail.Text = "Posture unavailable while the sensor service is offline";
                HardeningMetricValue.Text = "—";
                HardeningMetricDetail.Text = "Posture unavailable while the sensor service is offline";
                return;
            }
            _hardeningCheckedAt = DateTimeOffset.UtcNow;
            var antivirus = posture.Checks.FirstOrDefault(check => check.Id == "antivirus");
            AntivirusMetricValue.Text = antivirus?.State switch
            {
                PostureStates.Pass => "On",
                PostureStates.Finding => "At risk",
                _ => "Unknown",
            };
            AntivirusMetricDetail.Text = antivirus?.Detail ?? "Not reported by this version of the service";
            var findings = posture.Checks.Count(check => check.State == PostureStates.Finding);
            var unknown = posture.Checks.Count(check => check.State == PostureStates.Unknown);
            HardeningMetricValue.Text = findings.ToString("N0");
            HardeningMetricDetail.Text = $"of {posture.Checks.Count} checks · {unknown} need administrator rights or are unreadable";
        }
        finally
        {
            _securityRequestInFlight = false;
        }
    }

    private async Task RefreshSnapshotAsync()
    {
        if (_snapshotRequestInFlight) return;
        _snapshotRequestInFlight = true;
        try
        {
            var snapshot = await _snapshotClient.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _snapshotClient.TryGetSnapshotAsync();
            }

            if (snapshot is null)
            {
                SensorHeadline.Text = "Downpour is running · sensor service offline";
                SensorDescription.Text = $"{App.SensorServiceStatusHint} The chart stops at the last received sample.";
                SensorBadge.Text = "SERVICE OFFLINE";
                SensorDot.Fill = new SolidColorBrush(Color.FromArgb(255, 255, 180, 85));
                _cpuGauge?.SetValue(null);
                _memoryGauge?.SetValue(null);
                SetMetricCards("—", "Service connection unavailable", "—", "Service connection unavailable",
                    "—", "No current service data", "Offline", "No current measurements");
                CollectionReconciler.Apply(Processes, Array.Empty<DashboardProcessRow>(), row => row.ProcessId, (_, _) => { });
                ChartEmpty.Text = _history.Count > 0 ? "Service unavailable · awaiting a new sample" : "Awaiting live samples from Downpour.Service";
                ChartEmpty.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
                return;
            }

            App.MarkSensorServiceConnected();
            SensorHeadline.Text = "Sensor service connected · live";
            SensorDescription.Text = "Downpour is online with live local measurements updating every second. Detections feed Triage; response actions run only after you confirm each one.";
            SensorBadge.Text = "ONLINE";
            SensorDot.Fill = new SolidColorBrush(Color.FromArgb(255, 73, 227, 193));
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var usedBytes = snapshot.MemoryTotalBytes - Math.Min(snapshot.MemoryTotalBytes, snapshot.MemoryAvailableBytes);
            double? memoryPercent = snapshot.MemoryTotalBytes > 0 ? usedBytes * 100d / snapshot.MemoryTotalBytes : null;
            _cpuGauge?.SetValue(snapshot.CpuPercent);
            _memoryGauge?.SetValue(memoryPercent);
            _blossom.SetLoad(snapshot.CpuPercent ?? 0, memoryPercent ?? 0);

            SetMetricCards(snapshot.ProcessCount.ToString("N0"), "Current Windows process snapshot",
                snapshot.ActiveTcpConnections?.ToString("N0") ?? "—", "Current connection count",
                captured.ToString("HH:mm:ss"), captured.ToString("MMM d · h:mm:ss tt"),
                "Confirm to act", "Detection is automatic; quarantine, process, firewall, and USB actions need your confirmation");

            _history.Enqueue(new ResourceSample(snapshot.CpuPercent, memoryPercent));
            while (_history.Count > 120) _history.Dequeue();
            DrawResourceChart();

            var dashboardProcesses = snapshot.TopProcesses.Take(8).ToArray();
            var largestWorkingSet = dashboardProcesses.Length > 0 ? dashboardProcesses.Max(process => process.WorkingSetBytes) : 0;
            var dashboardRows = dashboardProcesses.Select(process => new DashboardProcessRow(
                process.ProcessId,
                process.Name,
                $"PID {process.ProcessId}  ·  {process.WorkingSetBytes / 1024d / 1024d:0} MB  ·  {process.ThreadCount} threads",
                largestWorkingSet > 0 ? Math.Clamp(process.WorkingSetBytes * 100d / largestWorkingSet, 0, 100) : 0)).ToArray();
            CollectionReconciler.Apply(Processes, dashboardRows, row => row.ProcessId, (current, incoming) =>
            {
                current.Name = incoming.Name;
                current.Detail = incoming.Detail;
                current.MemoryShare = incoming.MemoryShare;
            });
        }
        catch (Exception exception)
        {
            // The snapshot pipe can fail while the UI is starting or a service restarts.
            // Keep the app usable and never leave old data presented as a live sample.
            SensorHeadline.Text = "Downpour is running · current sensor sample unavailable";
            SensorDescription.Text = $"{App.SensorServiceStatusHint} {exception.GetType().Name}: {(exception.Message.Length > 180 ? exception.Message[..180] : exception.Message)}";
            SensorBadge.Text = "SAMPLE UNAVAILABLE";
            SensorDot.Fill = new SolidColorBrush(Color.FromArgb(255, 255, 180, 85));
            _cpuGauge?.SetValue(null);
            _memoryGauge?.SetValue(null);
            SetMetricCards("—", "Current sample unavailable", "—", "Current sample unavailable",
                "—", "No current service data", "Unknown", "Current sample unavailable");
            CollectionReconciler.Apply(Processes, Array.Empty<DashboardProcessRow>(), row => row.ProcessId, (_, _) => { });
            _history.Enqueue(new ResourceSample(null, null));
            while (_history.Count > 120) _history.Dequeue();
            DrawResourceChart();
            ChartEmpty.Text = "Sample unavailable · waiting for current telemetry";
            ChartEmpty.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
        }
        finally
        {
            _snapshotRequestInFlight = false;
        }
    }

    private void SetMetricCards(string processValue, string processDetail, string tcpValue, string tcpDetail,
        string snapshotValue, string snapshotDetail, string modeValue, string modeDetail)
    {
        ProcessMetricValue.Text = processValue;
        ProcessMetricDetail.Text = processDetail;
        TcpMetricValue.Text = tcpValue;
        TcpMetricDetail.Text = tcpDetail;
        SnapshotMetricValue.Text = snapshotValue;
        SnapshotMetricDetail.Text = snapshotDetail;
        SensorModeMetricValue.Text = modeValue;
        SensorModeMetricDetail.Text = modeDetail;
    }

    private void ResourceChartHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawResourceChart();

    private void DrawResourceChart()
    {
        if (ResourceChart is null) return;
        var width = ResourceChart.ActualWidth;
        var height = ResourceChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;
        const double insetX = 38;
        const double insetY = 7;
        _resourceGrid ??= new ChartGrid(ResourceChart, insetX, insetY, 31, 14, 9,
            Color.FromArgb(38, 190, 220, 242), Color.FromArgb(190, 164, 184, 199));
        _cpuSeries ??= new ChartLineRenderer(ResourceChart, Color.FromArgb(255, 80, 219, 241));
        _memorySeries ??= new ChartLineRenderer(ResourceChart, Color.FromArgb(255, 180, 122, 248));
        _resourceGrid.Update(width, height, ["100%", "75%", "50%", "25%", "0%"]);

        var samples = _history.ToArray();
        _cpuSeries.Update(MapSeries(samples.Select(sample => sample.CpuPercent).ToArray(), width, height, insetX, insetY), width - 8.1);
        _memorySeries.Update(MapSeries(samples.Select(sample => sample.MemoryPercent).ToArray(), width, height, insetX, insetY), width - 8.1);
        ChartEmpty.Visibility = samples.Any(sample => sample.CpuPercent.HasValue || sample.MemoryPercent.HasValue)
            ? Microsoft.UI.Xaml.Visibility.Collapsed
            : Microsoft.UI.Xaml.Visibility.Visible;
    }

    private static Point?[] MapSeries(double?[] values, double width, double height, double insetX, double insetY)
    {
        var points = new Point?[values.Length];
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] is not { } value) continue;
            var x = insetX + (width - insetX - 8) * index / Math.Max(1, values.Length - 1);
            var y = insetY + (height - insetY * 2) * (1 - Math.Clamp(value, 0, 100) / 100d);
            if (double.IsFinite(x) && double.IsFinite(y)) points[index] = new Point(x, y);
        }
        return points;
    }
}

public sealed class DashboardProcessRow : ObservableRow
{
    private int _processId;
    private string _name = "";
    private string _detail = "";
    private double _memoryShare;

    public DashboardProcessRow() { }
    public DashboardProcessRow(int processId, string name, string detail, double memoryShare) =>
        (_processId, _name, _detail, _memoryShare) = (processId, name, detail, memoryShare);
    public int ProcessId { get => _processId; set => SetProperty(ref _processId, value); }
    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string Detail { get => _detail; set => SetProperty(ref _detail, value); }
    public double MemoryShare { get => _memoryShare; set => SetProperty(ref _memoryShare, value); }
}

internal sealed record ResourceSample(double? CpuPercent, double? MemoryPercent);
