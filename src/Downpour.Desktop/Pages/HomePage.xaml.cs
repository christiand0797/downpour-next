using System.Collections.ObjectModel;
using Downpour.Core;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class HomePage : Page
{
    private readonly DispatcherQueueTimer _snapshotTimer;
    private readonly SystemSnapshotClient _snapshotClient = new();
    private readonly Queue<ResourceSample> _history = new();
    private bool _snapshotRequestInFlight;
    private CircularGauge? _cpuGauge;
    private CircularGauge? _memoryGauge;

    public ObservableCollection<MetricCard> Metrics { get; } =
    [
        new("Processes observed", "—", "Waiting for the local service"),
        new("Active TCP connections", "—", "Waiting for network telemetry"),
        new("Last snapshot", "—", "No current service data"),
        new("Sensor mode", "—", "Service status unavailable")
    ];

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
        if (!_snapshotTimer.IsRunning) _snapshotTimer.Start();
        _ = RefreshSnapshotAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _snapshotTimer.Stop();
        base.OnNavigatedFrom(e);
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
                SensorHeadline.Text = "Local sensor service is unavailable";
                SensorDescription.Text = "Start Downpour.Service to restore read-only measurements. The chart stops at the last received sample.";
                SensorBadge.Text = "OFFLINE";
                SensorDot.Fill = new SolidColorBrush(Color.FromArgb(255, 255, 180, 85));
                _cpuGauge?.SetValue(null);
                _memoryGauge?.SetValue(null);
                Metrics[0] = new("Processes observed", "—", "Service connection unavailable");
                Metrics[1] = new("Active TCP connections", "—", "Service connection unavailable");
                Metrics[2] = new("Last snapshot", "—", "No current service data");
                Metrics[3] = new("Sensor mode", "Offline", "No current measurements");
                Processes.Clear();
                ResourceChart.Children.Clear();
                ChartEmpty.Text = _history.Count > 0 ? "Service unavailable · awaiting a new sample" : "Awaiting live samples from Downpour.Service";
                ChartEmpty.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
                return;
            }

            SensorHeadline.Text = "Read-only sensor service connected";
            SensorDescription.Text = "Live Windows measurements are updating every three seconds. Detection and response engines are not connected yet.";
            SensorBadge.Text = "OBSERVE ONLY";
            SensorDot.Fill = new SolidColorBrush(Color.FromArgb(255, 73, 227, 193));
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var usedBytes = snapshot.MemoryTotalBytes - Math.Min(snapshot.MemoryTotalBytes, snapshot.MemoryAvailableBytes);
            double? memoryPercent = snapshot.MemoryTotalBytes > 0 ? usedBytes * 100d / snapshot.MemoryTotalBytes : null;
            _cpuGauge?.SetValue(snapshot.CpuPercent);
            _memoryGauge?.SetValue(memoryPercent);

            Metrics[0] = new("Processes observed", snapshot.ProcessCount.ToString("N0"), "Current Windows process snapshot");
            Metrics[1] = new("Active TCP connections", snapshot.ActiveTcpConnections?.ToString("N0") ?? "—", "Current connection count");
            Metrics[2] = new("Last snapshot", captured.ToString("HH:mm:ss"), captured.ToString("MMM d · h:mm:ss tt"));
            Metrics[3] = new("Sensor mode", "Observe only", "No system-changing actions enabled");

            _history.Enqueue(new ResourceSample(snapshot.CpuPercent, memoryPercent));
            while (_history.Count > 60) _history.Dequeue();
            DrawResourceChart();

            Processes.Clear();
            var largestWorkingSet = snapshot.TopProcesses.Count > 0 ? snapshot.TopProcesses.Max(process => process.WorkingSetBytes) : 0;
            foreach (var process in snapshot.TopProcesses)
            {
                var share = largestWorkingSet > 0 ? Math.Clamp(process.WorkingSetBytes * 100d / largestWorkingSet, 0, 100) : 0;
                Processes.Add(new DashboardProcessRow(
                    process.Name,
                    $"PID {process.ProcessId}  ·  {process.WorkingSetBytes / 1024d / 1024d:0} MB  ·  {process.ThreadCount} threads",
                    share));
            }
        }
        finally
        {
            _snapshotRequestInFlight = false;
        }
    }

    private void ResourceChartHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawResourceChart();

    private void DrawResourceChart()
    {
        if (ResourceChart is null) return;
        var width = ResourceChart.ActualWidth;
        var height = ResourceChart.ActualHeight;
        ResourceChart.Children.Clear();
        if (width <= 0 || height <= 0) return;

        const double insetX = 12;
        const double insetY = 7;
        for (var index = 0; index <= 4; index++)
        {
            var y = insetY + (height - insetY * 2) * index / 4;
            var guide = new Line
            {
                X1 = insetX,
                X2 = Math.Max(insetX, width - insetX),
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

            var x = insetX + (width - insetX * 2) * index / Math.Max(1, samples.Length - 1);
            var y = insetY + (height - insetY * 2) * (1 - Math.Clamp(value.Value, 0, 100) / 100d);
            segment.Add(new Point(x, y));
        }
        AddSegment();

        void AddSegment()
        {
            if (segment.Count >= 2)
            {
                var points = new PointCollection();
                foreach (var point in segment) points.Add(point);
                ResourceChart.Children.Add(new Polyline
                {
                    Points = points,
                    Stroke = new SolidColorBrush(color),
                    StrokeThickness = 2.2,
                    StrokeLineJoin = PenLineJoin.Round
                });
            }
            else if (segment.Count == 1)
            {
                var point = segment[0];
                ResourceChart.Children.Add(new Ellipse
                {
                    Width = 5,
                    Height = 5,
                    Fill = new SolidColorBrush(color)
                });
                var marker = ResourceChart.Children[ResourceChart.Children.Count - 1];
                Canvas.SetLeft(marker, point.X - 2.5);
                Canvas.SetTop(marker, point.Y - 2.5);
            }
            segment.Clear();
        }
    }
}

public sealed class MetricCard
{
    public MetricCard() { }
    public MetricCard(string label, string value, string detail) => (Label, Value, Detail) = (label, value, detail);
    public string Label { get; set; } = "";
    public string Value { get; set; } = "";
    public string Detail { get; set; } = "";
}

public sealed class DashboardProcessRow
{
    public DashboardProcessRow() { }
    public DashboardProcessRow(string name, string detail, double memoryShare) => (Name, Detail, MemoryShare) = (name, detail, memoryShare);
    public string Name { get; set; } = "";
    public string Detail { get; set; } = "";
    public double MemoryShare { get; set; }
}

internal sealed record ResourceSample(double? CpuPercent, double? MemoryPercent);
