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
                NetworkHeadline.Text = "Network sensor service unavailable";
                NetworkDescription.Text = "No cached or substituted values are shown. Reconnect the local service to resume collection.";
                ReceiveRate.Text = "—";
                SendRate.Text = "—";
                ConnectionCount.Text = "—";
                Interfaces.Clear();
                Connections.Clear();
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

            Interfaces.Clear();
            foreach (var row in snapshot.Interfaces.OrderByDescending(row => row.Status == "Up").ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase))
            {
                Interfaces.Add(new NetworkInterfaceRow(
                    row.Name,
                    $"{row.Description} · received {row.TotalReceivedBytes:N0} B · sent {row.TotalSentBytes:N0} B",
                    row.Status,
                    row.ReceiveBytesPerSecond is { } rx ? FormatRate(rx) : "↓  —",
                    row.SendBytesPerSecond is { } tx ? FormatRate(tx) : "↑  —",
                    row.TotalReceivedBytes is >= 0 ? FormatBytes(row.TotalReceivedBytes) : "—",
                    row.TotalSentBytes is >= 0 ? FormatBytes(row.TotalSentBytes) : "—"));
            }

            Connections.Clear();
            foreach (var row in snapshot.Connections)
            {
                Connections.Add(new NetworkConnectionRow(row.LocalEndpoint, row.RemoteEndpoint, row.State));
            }
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
        if (width <= 1 || height <= 1) return;

        var values = _history.ToArray();
        for (var level = 1; level <= 3; level++)
        {
            var y = height * level / 4;
            var line = new Line { X1 = 0, X2 = width, Y1 = y, Y2 = y, Stroke = new SolidColorBrush(Color.FromArgb(44, 161, 190, 211)), StrokeThickness = 1 };
            HistoryChart.Children.Add(line);
        }

        var max = Math.Max(1024, values.SelectMany(point => new[] { point.Receive, point.Send }).Where(value => value.HasValue).Select(value => (double)value!.Value).DefaultIfEmpty(0).Max());
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

            var x = values.Length <= 1 ? width : index * width / (values.Length - 1);
            var y = height - 4 - (Math.Clamp(value / max, 0, 1) * (height - 8));
            segment.Add(new Windows.Foundation.Point(x, y));
        }
        AddSegment();

        void AddSegment()
        {
            if (segment.Count >= 2)
            {
                var line = new Polyline
                {
                    Points = new PointCollection(),
                    Stroke = new SolidColorBrush(color),
                    StrokeThickness = 2,
                    StrokeLineJoin = PenLineJoin.Round
                };
                foreach (var point in segment) line.Points.Add(point);
                HistoryChart.Children.Add(line);
            }
            else if (segment.Count == 1)
            {
                var point = segment[0];
                HistoryChart.Children.Add(new Ellipse { Width = 4, Height = 4, Fill = new SolidColorBrush(color), Margin = new Microsoft.UI.Xaml.Thickness(-2) });
                Canvas.SetLeft(HistoryChart.Children[^1], point.X);
                Canvas.SetTop(HistoryChart.Children[^1], point.Y);
            }
            segment.Clear();
        }
    }

    private sealed record NetworkPoint(long? Receive, long? Send);
}

public sealed class NetworkInterfaceRow(string name, string detail, string status, string receiveRate, string sendRate, string receivedTotal, string sentTotal)
{
    public string Name { get; } = name;
    public string Detail { get; } = detail;
    public string Status { get; } = status;
    public string ReceiveRate { get; } = receiveRate;
    public string SendRate { get; } = sendRate;
    public string ReceivedTotal { get; } = receivedTotal;
    public string SentTotal { get; } = sentTotal;
}

public sealed class NetworkConnectionRow
{
    public NetworkConnectionRow() { }

    public NetworkConnectionRow(string localEndpoint, string remoteEndpoint, string state) =>
        (LocalEndpoint, RemoteEndpoint, State) = (localEndpoint, remoteEndpoint, state);

    public string LocalEndpoint { get; set; } = "";
    public string RemoteEndpoint { get; set; } = "";
    public string State { get; set; } = "";
}
