using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class NetworkPage : Page
{
    private const int HistoryLimit = 60;
    private readonly NetworkInventoryClient _client = new();
    private readonly DispatcherQueueTimer _refreshTimer;
    private readonly Queue<NetworkPoint> _history = new();
    private bool _requestInFlight;

    public ObservableCollection<NetworkInterfaceRow> Interfaces { get; } = [];
    public ObservableCollection<NetworkConnectionRow> Connections { get; } = [];

    public NetworkPage()
    {
        InitializeComponent();
        _refreshTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _refreshTimer.Interval = TimeSpan.FromSeconds(3);
        _refreshTimer.IsRepeating = true;
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
        _refreshTimer.Start();
        _ = RefreshAsync();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (!_refreshTimer.IsRunning) _refreshTimer.Start();
        _ = RefreshAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _refreshTimer.Stop();
        base.OnNavigatedFrom(e);
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            if (snapshot is null)
            {
                NetworkHeadline.Text = "Downpour is running · network sensor offline";
                NetworkDescription.Text = $"{App.SensorServiceStatusHint} No cached or substituted values are shown.";
                ReceiveRate.Text = "—";
                SendRate.Text = "—";
                ConnectionCount.Text = "—";
                CollectionReconciler.Apply(Interfaces, Array.Empty<NetworkInterfaceRow>(), row => row.Name, (_, _) => { });
                CollectionReconciler.Apply(Connections, Array.Empty<NetworkConnectionRow>(), row => row.Key, (_, _) => { });
                _history.Enqueue(new NetworkPoint(null, null));
                TrimHistory();
                DrawHistory();
                return;
            }

            var activeRates = snapshot.Interfaces.Where(row => row.Status == "Up").ToArray();
            var receive = SumRates(activeRates.Select(row => row.ReceiveBytesPerSecond));
            var send = SumRates(activeRates.Select(row => row.SendBytesPerSecond));
            ReceiveRate.Text = receive is { } received ? FormatRate(received) : "Waiting for second sample";
            SendRate.Text = send is { } sent ? FormatRate(sent) : "Waiting for second sample";
            ConnectionCount.Text = snapshot.TotalConnectionCount.ToString("N0");
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            NetworkHeadline.Text = $"Read-only network inventory connected · captured {captured:HH:mm:ss}";
            NetworkDescription.Text = snapshot.Warnings.Count == 0
                ? "Interface totals and active TCP endpoints are collected locally. Throughput uses counter deltas."
                : string.Join(" ", snapshot.Warnings);

            var interfaceRows = snapshot.Interfaces.OrderByDescending(row => row.Status == "Up").ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
                .Select(row => new NetworkInterfaceRow(
                    row.Name,
                    $"{row.Description} · received {row.TotalReceivedBytes:N0} B · sent {row.TotalSentBytes:N0} B",
                    row.Status,
                    row.ReceiveBytesPerSecond is { } rx ? FormatRate(rx) : "↓  —",
                    row.SendBytesPerSecond is { } tx ? FormatRate(tx) : "↑  —",
                    row.TotalReceivedBytes is >= 0 ? FormatBytes(row.TotalReceivedBytes) : "—",
                    row.TotalSentBytes is >= 0 ? FormatBytes(row.TotalSentBytes) : "—")).ToArray();
            CollectionReconciler.Apply(Interfaces, interfaceRows, row => row.Name, (current, incoming) =>
            {
                current.Detail = incoming.Detail;
                current.Status = incoming.Status;
                current.ReceiveRate = incoming.ReceiveRate;
                current.SendRate = incoming.SendRate;
                current.ReceivedTotal = incoming.ReceivedTotal;
                current.SentTotal = incoming.SentTotal;
            });

            var connectionRows = snapshot.Connections.Select(row => new NetworkConnectionRow(row.LocalEndpoint, row.RemoteEndpoint, row.State)).ToArray();
            CollectionReconciler.Apply(Connections, connectionRows, row => row.Key, (current, incoming) => current.State = incoming.State);
            ConnectionEmpty.Visibility = Connections.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
            ConnectionFootnote.Text = snapshot.TotalConnectionCount > snapshot.Connections.Count
                ? $"SHOWING {snapshot.Connections.Count:N0} OF {snapshot.TotalConnectionCount:N0}"
                : $"{Connections.Count:N0} LOCAL ENDPOINTS";

            _history.Enqueue(new NetworkPoint(receive, send));
            TrimHistory();
            DrawHistory();
        }
        finally
        {
            _requestInFlight = false;
        }
    }

    private static long? SumRates(IEnumerable<long?> values)
    {
        var available = values.Where(value => value.HasValue).Select(value => value!.Value).ToArray();
        return available.Length == 0 ? null : available.Aggregate(0L, (sum, value) => sum > long.MaxValue - value ? long.MaxValue : sum + value);
    }

    private static string FormatRate(long bytesPerSecond) => $"{FormatBytes(bytesPerSecond)}/s";

    private static string FormatBytes(long bytes)
    {
        var value = (double)Math.Max(0, bytes);
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{value:0} {units[unit]}" : $"{value:0.0} {units[unit]}";
    }

    private void TrimHistory()
    {
        while (_history.Count > HistoryLimit) _history.Dequeue();
    }

    private void HistoryHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawHistory();

    private void DrawHistory()
    {
        if (HistoryChart is null) return;
        HistoryChart.Children.Clear();
        var width = HistoryChart.ActualWidth;
        var height = HistoryChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;

        var values = _history.ToArray();
        for (var level = 1; level <= 3; level++)
        {
            var y = height * level / 4;
            var line = new Line { X1 = 0, X2 = width, Y1 = y, Y2 = y, Stroke = new SolidColorBrush(Color.FromArgb(44, 161, 190, 211)), StrokeThickness = 1 };
            HistoryChart.Children.Add(line);
        }

        var max = Math.Max(1024, values.SelectMany(point => new[] { point.Receive, point.Send }).Where(value => value.HasValue).Select(value => (double)value!.Value).DefaultIfEmpty(0).Max());
        HistoryScale.Text = $"Peak {FormatRate((long)Math.Min(max, long.MaxValue))}";
        DrawSeries(values.Select(point => point.Receive).ToArray(), width, height, max, Color.FromArgb(255, 80, 219, 241));
        DrawSeries(values.Select(point => point.Send).ToArray(), width, height, max, Color.FromArgb(255, 180, 122, 248));
    }

    private void DrawSeries(long?[] values, double width, double height, double max, Color color)
    {
        var segment = new List<Windows.Foundation.Point>();
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] is not { } value)
            {
                AddSegment();
                continue;
            }

            const double inset = 4;
            var x = inset + (width - inset * 2) * index / Math.Max(1, values.Length - 1);
            var y = inset + (height - inset * 2) * (1 - Math.Clamp(value / max, 0, 1));
            if (!double.IsFinite(x) || !double.IsFinite(y)) { AddSegment(); continue; }
            segment.Add(new Windows.Foundation.Point(x, y));
        }
        AddSegment();

        void AddSegment()
        {
            if (segment.Count >= 2)
            {
                var glowPoints = new PointCollection();
                foreach (var point in segment) glowPoints.Add(point);
                var line = new Polyline
                {
                    Points = glowPoints,
                    Stroke = new SolidColorBrush(Color.FromArgb(30, color.R, color.G, color.B)),
                    StrokeThickness = 8,
                    StrokeLineJoin = PenLineJoin.Round
                };
                HistoryChart.Children.Add(line);
                var crispPoints = new PointCollection();
                foreach (var point in segment) crispPoints.Add(point);
                var crisp = new Polyline
                {
                    Points = crispPoints,
                    Stroke = new SolidColorBrush(color),
                    StrokeThickness = 2,
                    StrokeLineJoin = PenLineJoin.Round
                };
                HistoryChart.Children.Add(crisp);
            }
            if (segment.Count > 0 && values.Length > 0 && segment[^1].X >= width - 4.1)
            {
                AddMarker(segment[^1], 12, Color.FromArgb(36, color.R, color.G, color.B));
                AddMarker(segment[^1], 5, color);
            }
            else if (segment.Count == 1)
            {
                AddMarker(segment[0], 5, color);
            }
            segment.Clear();
        }

        void AddMarker(Windows.Foundation.Point point, double size, Color fill)
        {
            var marker = new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(fill) };
            HistoryChart.Children.Add(marker);
            Canvas.SetLeft(marker, point.X - size / 2);
            Canvas.SetTop(marker, point.Y - size / 2);
        }
    }

    private sealed record NetworkPoint(long? Receive, long? Send);
}

public sealed class NetworkInterfaceRow : ObservableRow
{
    private string _name = "";
    private string _detail = "";
    private string _status = "";
    private string _receiveRate = "";
    private string _sendRate = "";
    private string _receivedTotal = "";
    private string _sentTotal = "";

    public NetworkInterfaceRow() { }
    public NetworkInterfaceRow(string name, string detail, string status, string receiveRate, string sendRate, string receivedTotal, string sentTotal) =>
        (_name, _detail, _status, _receiveRate, _sendRate, _receivedTotal, _sentTotal) = (name, detail, status, receiveRate, sendRate, receivedTotal, sentTotal);

    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string Detail { get => _detail; set => SetProperty(ref _detail, value); }
    public string Status { get => _status; set => SetProperty(ref _status, value); }
    public string ReceiveRate { get => _receiveRate; set => SetProperty(ref _receiveRate, value); }
    public string SendRate { get => _sendRate; set => SetProperty(ref _sendRate, value); }
    public string ReceivedTotal { get => _receivedTotal; set => SetProperty(ref _receivedTotal, value); }
    public string SentTotal { get => _sentTotal; set => SetProperty(ref _sentTotal, value); }
}

public sealed class NetworkConnectionRow : ObservableRow
{
    private string _localEndpoint = "";
    private string _remoteEndpoint = "";
    private string _state = "";
    public NetworkConnectionRow() { }

    public NetworkConnectionRow(string localEndpoint, string remoteEndpoint, string state) =>
        (_localEndpoint, _remoteEndpoint, _state) = (localEndpoint, remoteEndpoint, state);

    public string Key => $"{LocalEndpoint}\u001f{RemoteEndpoint}";
    public string LocalEndpoint { get => _localEndpoint; set => SetProperty(ref _localEndpoint, value); }
    public string RemoteEndpoint { get => _remoteEndpoint; set => SetProperty(ref _remoteEndpoint, value); }
    public string State { get => _state; set => SetProperty(ref _state, value); }
}
