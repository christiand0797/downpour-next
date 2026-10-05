using System.Collections.ObjectModel;
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
    private CircularGauge? _cpuGauge;
    private CircularGauge? _memoryGauge;

    public ObservableCollection<DashboardProcessRow> Processes { get; } = [];

    public HomePage()
    {
        InitializeComponent();
        _cpuGauge = new CircularGauge("CPU", Color.FromArgb(255, 74, 220, 243));
        _memoryGauge = new CircularGauge("MEMORY", Color.FromArgb(255, 178, 121, 248));
        GaugeHost.Children.Add(_cpuGauge);
        GaugeHost.Children.Add(_memoryGauge);

        _snapshotTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _snapshotTimer.Interval = TimeSpan.FromSeconds(3);
        _snapshotTimer.IsRepeating = true;
        _snapshotTimer.Tick += async (_, _) => await RefreshSnapshotAsync();
        _snapshotTimer.Start();
        _ = RefreshSnapshotAsync();
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
            SensorHeadline.Text = "Read-only sensor service connected";
            SensorDescription.Text = "Downpour is online with live local measurements updating every three seconds. Detection and response engines are not connected yet.";
            SensorBadge.Text = "ONLINE";
            SensorDot.Fill = new SolidColorBrush(Color.FromArgb(255, 73, 227, 193));
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var usedBytes = snapshot.MemoryTotalBytes - Math.Min(snapshot.MemoryTotalBytes, snapshot.MemoryAvailableBytes);
            double? memoryPercent = snapshot.MemoryTotalBytes > 0 ? usedBytes * 100d / snapshot.MemoryTotalBytes : null;
            _cpuGauge?.SetValue(snapshot.CpuPercent);
            _memoryGauge?.SetValue(memoryPercent);

            SetMetricCards(snapshot.ProcessCount.ToString("N0"), "Current Windows process snapshot",
                snapshot.ActiveTcpConnections?.ToString("N0") ?? "—", "Current connection count",
                captured.ToString("HH:mm:ss"), captured.ToString("MMM d · h:mm:ss tt"),
                "Observe only", "No system-changing actions enabled");

            _history.Enqueue(new ResourceSample(snapshot.CpuPercent, memoryPercent));
            while (_history.Count > 60) _history.Dequeue();
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
            while (_history.Count > 60) _history.Dequeue();
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
        ResourceChart.Children.Clear();

        const double insetX = 38;
        const double insetY = 7;
        for (var index = 0; index <= 4; index++)
        {
            var y = insetY + (height - insetY * 2) * index / 4;
            var axisLabel = new TextBlock
            {
                Text = $"{100 - index * 25}%",
                Width = 31,
                Height = 14,
                FontSize = 9,
                Foreground = new SolidColorBrush(Color.FromArgb(190, 164, 184, 199)),
                HorizontalTextAlignment = Microsoft.UI.Xaml.TextAlignment.Right
            };
            ResourceChart.Children.Add(axisLabel);
            Canvas.SetLeft(axisLabel, 0);
            Canvas.SetTop(axisLabel, Math.Clamp(y - 7, 0, Math.Max(0, height - 14)));
        }
        for (var index = 0; index <= 4; index++)
        {
            var y = insetY + (height - insetY * 2) * index / 4;
            var guide = new Line
            {
                X1 = insetX,
                X2 = Math.Max(insetX, width - 8),
                Y1 = y,
                Y2 = y,
                StrokeThickness = 1,
                Stroke = new SolidColorBrush(Color.FromArgb(38, 190, 220, 242))
            };
            ResourceChart.Children.Add(guide);
        }

        var samples = _history.ToArray();
        if (samples.Length >= 2)
        {
            DrawSeries(samples, sample => sample.CpuPercent, Color.FromArgb(255, 80, 219, 241), width, height, insetX, insetY);
            DrawSeries(samples, sample => sample.MemoryPercent, Color.FromArgb(255, 180, 122, 248), width, height, insetX, insetY);
        }
        ChartEmpty.Visibility = samples.Any(sample => sample.CpuPercent.HasValue || sample.MemoryPercent.HasValue)
            ? Microsoft.UI.Xaml.Visibility.Collapsed
            : Microsoft.UI.Xaml.Visibility.Visible;
    }

    private void DrawSeries(ResourceSample[] samples, Func<ResourceSample, double?> selector, Color color,
        double width, double height, double insetX, double insetY)
    {
        var segment = new List<Point>();
        for (var index = 0; index < samples.Length; index++)
        {
            var value = selector(samples[index]);
            if (value is null)
            {
                AddSegment();
                continue;
            }

            var x = insetX + (width - insetX - 8) * index / Math.Max(1, samples.Length - 1);
            var y = insetY + (height - insetY * 2) * (1 - Math.Clamp(value.Value, 0, 100) / 100d);
            if (!double.IsFinite(x) || !double.IsFinite(y)) { AddSegment(); continue; }
            segment.Add(new Point(x, y));
        }
        AddSegment();

        void AddSegment()
        {
            if (segment.Count >= 2) ChartLineRenderer.Add(ResourceChart, segment, color);
            // A single bright endpoint marks only the newest real sample; null gaps are
            // never bridged or presented as current data.
            if (segment.Count > 0 && segment[^1].X >= width - 8.1)
            {
                AddMarker(segment[^1], 12, Color.FromArgb(35, color.R, color.G, color.B));
                AddMarker(segment[^1], 5, color);
            }
            else if (segment.Count == 1) AddMarker(segment[0], 5, color);
            segment.Clear();
        }

        void AddMarker(Point point, double size, Color fill)
        {
            var marker = new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(fill) };
            ResourceChart.Children.Add(marker);
            Canvas.SetLeft(marker, point.X - size / 2);
            Canvas.SetTop(marker, point.Y - size / 2);
        }
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
