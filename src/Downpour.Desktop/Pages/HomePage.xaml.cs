using System.Collections.ObjectModel;
using Downpour.Core;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class HomePage : Page
{
    private readonly List<RainDrop> _rainDrops = [];
    private readonly Random _random = new();
    private DispatcherQueueTimer? _rainTimer;
    private readonly DispatcherQueueTimer _snapshotTimer;
    private readonly SystemSnapshotClient _snapshotClient = new();
    private bool _snapshotRequestInFlight;

    public ObservableCollection<MetricCard> Metrics { get; } =
    [
        new("Sensor service", "Disconnected", "Live telemetry is unavailable"),
        new("Processes observed", "—", "Waiting for the process sensor"),
        new("Open security alerts", "—", "Alert pipeline is not connected"),
        new("Active TCP connections", "—", "Waiting for network telemetry"),
        new("CPU utilization", "—", "Waiting for the first sample"),
        new("Physical memory", "—", "Waiting for system telemetry"),
        new("Threat intelligence", "—", "Feed health is not available yet"),
        new("Last updated", "—", "Waiting for sensor data")
    ];

    public ObservableCollection<DashboardProcessRow> Processes { get; } = [];

    public HomePage()
    {
        InitializeComponent();
        _snapshotTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _snapshotTimer.Interval = TimeSpan.FromSeconds(3);
        _snapshotTimer.IsRepeating = true;
        _snapshotTimer.Tick += async (_, _) => await RefreshSnapshotAsync();
        _snapshotTimer.Start();
        _ = RefreshSnapshotAsync();
    }

    private void RainBanner_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e)
    {
        if (_rainDrops.Count == 0 && RainBanner.ActualWidth > 0)
        {
            for (var index = 0; index < 76; index++)
            {
                var height = _random.Next(9, 27);
                var drop = new Rectangle
                {
                    Width = _random.Next(1, 3),
                    Height = height,
                    Opacity = _random.NextDouble() * 0.42 + 0.12,
                    Fill = new SolidColorBrush(Color.FromArgb(255, 89, (byte)_random.Next(185, 232), 255))
                };
                _rainDrops.Add(new RainDrop(drop, _random.NextDouble() * RainBanner.ActualWidth, _random.NextDouble() * 188, _random.Next(4, 10)));
                RainCanvas.Children.Add(drop);
                Canvas.SetLeft(drop, _rainDrops[^1].X);
                Canvas.SetTop(drop, _rainDrops[^1].Y);
            }

            _rainTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
            _rainTimer.Interval = TimeSpan.FromMilliseconds(40);
            _rainTimer.IsRepeating = true;
            _rainTimer.Tick += (_, _) => AnimateRain();
            _rainTimer.Start();
        }
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (!_snapshotTimer.IsRunning) _snapshotTimer.Start();
        if (_rainDrops.Count > 0 && _rainTimer is { IsRunning: false }) _rainTimer.Start();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _snapshotTimer.Stop();
        _rainTimer?.Stop();
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
                SensorHeadline.Text = "Sensor service is not connected";
                SensorDescription.Text = "Start Downpour.Service to show live read-only process, CPU, memory, and TCP telemetry.";
                SensorBadge.Text = "OFFLINE";
                Metrics[0] = new("Sensor service", "Disconnected", "Run the service project to connect");
                Metrics[1] = new("Processes observed", "—", "Service connection unavailable");
                Metrics[3] = new("Active TCP connections", "—", "Service connection unavailable");
                Metrics[4] = new("CPU utilization", "—", "Service connection unavailable");
                Metrics[5] = new("Physical memory", "—", "Service connection unavailable");
                Metrics[7] = new("Last updated", "—", "No current service data");
                Processes.Clear();
                return;
            }

            SensorHeadline.Text = "Read-only sensor service connected";
            SensorDescription.Text = "Live Windows telemetry is available. Detection engines and response actions are not connected in this build.";
            SensorBadge.Text = "OBSERVE ONLY";
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            Metrics[0] = new("Sensor service", "Connected", "Read-only mode; no system changes");
            Metrics[1] = new("Processes observed", snapshot.ProcessCount.ToString("N0"), "Current Windows process snapshot");
            Metrics[3] = new("Active TCP connections", snapshot.ActiveTcpConnections?.ToString("N0") ?? "—", "Current local connection count");
            Metrics[4] = new("CPU utilization", snapshot.CpuPercent is double cpu ? $"{cpu:0.0}%" : "Sampling…", "System-wide processor activity");
            var memoryTotalGb = snapshot.MemoryTotalBytes / 1024d / 1024d / 1024d;
            var memoryUsedGb = (snapshot.MemoryTotalBytes - Math.Min(snapshot.MemoryTotalBytes, snapshot.MemoryAvailableBytes)) / 1024d / 1024d / 1024d;
            Metrics[5] = new("Physical memory", snapshot.MemoryTotalBytes > 0 ? $"{memoryUsedGb:0.0} / {memoryTotalGb:0.0} GB" : "—", "Used / total system memory");
            Metrics[7] = new("Last updated", captured.ToString("HH:mm:ss"), $"Snapshot at {captured:g}");
            Processes.Clear();
            foreach (var process in snapshot.TopProcesses)
            {
                Processes.Add(new DashboardProcessRow(process.Name, $"PID {process.ProcessId}  ·  {process.WorkingSetBytes / 1024d / 1024d:0} MB  ·  {process.ThreadCount} threads"));
            }
        }
        finally
        {
            _snapshotRequestInFlight = false;
        }
    }

    private void AnimateRain()
    {
        var width = RainBanner.ActualWidth;
        if (width <= 0) return;

        foreach (var drop in _rainDrops)
        {
            drop.Y += drop.Speed;
            if (drop.Y > RainBanner.ActualHeight)
            {
                drop.Y = -drop.Shape.Height;
                drop.X = _random.NextDouble() * width;
            }
            Canvas.SetLeft(drop.Shape, drop.X);
            Canvas.SetTop(drop.Shape, drop.Y);
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
    public DashboardProcessRow(string name, string detail) => (Name, Detail) = (name, detail);
    public string Name { get; set; } = "";
    public string Detail { get; set; } = "";
}

internal sealed class RainDrop(Rectangle shape, double x, double y, double speed)
{
    public Rectangle Shape { get; } = shape;
    public double X { get; set; } = x;
    public double Y { get; set; } = y;
    public double Speed { get; } = speed;
}
