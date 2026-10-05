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
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class PerformancePage : Page
{
    private const int HistoryLimit = 40; // 40 × 3 seconds = two minutes.
    private readonly SystemSnapshotClient _client = new();
    private readonly NetworkInventoryClient _networkClient = new();
    private readonly DispatcherQueueTimer _timer;
    private readonly Queue<PerformanceSample> _history = new();
    private readonly CircularGauge _cpuGauge;
    private readonly CircularGauge _memoryGauge;
    private readonly CircularGauge _commitGauge;
    private readonly CircularGauge _diskGauge;
    private readonly CircularGauge _receiveGauge;
    private readonly CircularGauge _sendGauge;
    private readonly CircularGauge _diskReadGauge;
    private readonly CircularGauge _diskWriteGauge;
    private bool _requestInFlight;
    private bool _samplingPaused;
    private bool _exportInFlight;

    public ObservableCollection<PerformanceProcessRow> Processes { get; } = [];

    public PerformancePage()
    {
        InitializeComponent();
        _cpuGauge = new CircularGauge("CPU", Color.FromArgb(255, 74, 220, 243));
        _memoryGauge = new CircularGauge("MEMORY", Color.FromArgb(255, 178, 121, 248));
        _commitGauge = new CircularGauge("COMMIT", Color.FromArgb(255, 255, 174, 92));
        _diskGauge = new CircularGauge("OS DISK", Color.FromArgb(255, 255, 176, 94));
        _receiveGauge = new CircularGauge("RX / s", Color.FromArgb(255, 80, 219, 241));
        _sendGauge = new CircularGauge("TX / s", Color.FromArgb(255, 180, 122, 248));
        _diskReadGauge = new CircularGauge("DISK READ", Color.FromArgb(255, 255, 174, 92));
        _diskWriteGauge = new CircularGauge("DISK WRITE", Color.FromArgb(255, 180, 122, 248));
        AddGauge(_cpuGauge, 0, 0);
        AddGauge(_memoryGauge, 1, 0);
        AddGauge(_diskGauge, 2, 0);
        AddGauge(_receiveGauge, 0, 1);
        AddGauge(_sendGauge, 1, 1);
        AddGauge(_commitGauge, 2, 1);
        AddGauge(_diskReadGauge, 0, 2);
        AddGauge(_diskWriteGauge, 1, 2);
        CpuCount.Text = Environment.ProcessorCount.ToString("N0");
        CpuDetail.Text = "Logical processors · Windows reports topology only";
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(3);
        _timer.IsRepeating = true;
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
    }

    private void AddGauge(CircularGauge gauge, int column, int row)
    {
        GaugeHost.Children.Add(gauge);
        Grid.SetColumn(gauge, column);
        Grid.SetRow(gauge, row);
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (!_samplingPaused && !_timer.IsRunning) _timer.Start();
        _ = RefreshAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _timer.Stop();
        base.OnNavigatedFrom(e);
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private void Pause_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        _samplingPaused = !_samplingPaused;
        if (_samplingPaused) _timer.Stop();
        else if (IsLoaded && !_timer.IsRunning) _timer.Start();
        PauseButton.Content = _samplingPaused ? "▶  Resume" : "Ⅱ  Pause";
        ToolTipService.SetToolTip(PauseButton, _samplingPaused
            ? "Resume automatic three-second sampling."
            : "Pause automatic three-second sampling.");
        StatusDescription.Text = _samplingPaused
            ? "Automatic sampling is paused. Use Refresh for a one-time current snapshot."
            : "CPU, memory, commit, and adapter rates update every three seconds. Missing readings remain visible as graph gaps.";
    }

    private async void Export_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        var samples = _history.ToArray();
        if (_exportInFlight || samples.Length == 0) return;
        _exportInFlight = true;
        ExportButton.IsEnabled = false;
        try
        {
            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = $"Downpour-Performance-{DateTimeOffset.Now:yyyyMMdd-HHmmss}"
            };
            picker.FileTypeChoices.Add("CSV performance history", new List<string> { ".csv" });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            var file = await picker.PickSaveFileAsync();
            if (file is null)
            {
                StatusHeadline.Text = "Performance export cancelled";
                return;
            }

            var csv = new System.Text.StringBuilder("captured_at_local,cpu_percent,memory_percent,commit_percent,committed_bytes,commit_limit_bytes,receive_bytes_per_second,send_bytes_per_second,disk_read_bytes_per_second,disk_write_bytes_per_second\r\n");
            foreach (var sample in samples)
            {
                csv.Append(sample.CapturedAtUtc.ToLocalTime().ToString("O"))
                    .Append(',').Append(sample.Cpu?.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.Memory?.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.CommitPercent?.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.CommittedBytes?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.CommitLimitBytes?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.Receive?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.Send?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.DiskRead?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append(',').Append(sample.DiskWrite?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "")
                    .Append("\r\n");
            }
            await FileIO.WriteTextAsync(file, csv.ToString());
            StatusHeadline.Text = "Performance history exported";
            StatusDescription.Text = $"Saved {samples.Length:N0} bounded samples. Empty metric cells mark unavailable readings.";
        }
        catch (Exception exception)
        {
            StatusHeadline.Text = "Performance export failed";
            StatusDescription.Text = $"The file was not confirmed as saved ({exception.GetType().Name}). Choose another local destination and retry.";
        }
        finally
        {
            _exportInFlight = false;
            ExportButton.IsEnabled = _history.Count > 0;
        }
    }

    private async Task RefreshAsync()
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        try
        {
            var volume = await Task.Run(ReadSystemVolume);
            _diskGauge.SetMetric(volume.UsagePercent, volume.DisplayValue);
            DiskValue.Text = volume.Value;
            DiskDetail.Text = volume.Detail;
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            if (snapshot is null)
            {
                ServiceState.Text = "SERVICE OFFLINE";
                ServiceDot.Fill = new SolidColorBrush(Color.FromArgb(255, 255, 180, 85));
                StatusHeadline.Text = "Downpour is running · performance sensor offline";
                StatusDescription.Text = $"{App.SensorServiceStatusHint} New graph samples will resume when local telemetry reconnects.";
                _cpuGauge.SetValue(null);
                _memoryGauge.SetValue(null);
                _commitGauge.SetMetric(null, null);
                _receiveGauge.SetMetric(null, null);
                _sendGauge.SetMetric(null, null);
                _diskReadGauge.SetMetric(null, null);
                _diskWriteGauge.SetMetric(null, null);
                MemorySummary.Text = "Physical memory totals are unavailable with the sensor offline";
                CommitSummary.Text = "System commit counters unavailable";
                DiskIoSummary.Text = "Physical disk counters unavailable with the sensor offline";
                ProcessCount.Text = "—";
                ConnectionCount.Text = "—";
                UptimeValue.Text = FormatUptime(TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64)));
                CollectionReconciler.Apply(Processes, Array.Empty<PerformanceProcessRow>(), row => row.ProcessId, (_, _) => { });
                _history.Enqueue(new PerformanceSample(DateTimeOffset.UtcNow, null, null, null, null, null, null, null, null, null));
                TrimHistory();
                DrawHistory();
                DrawNetworkHistory();
                DrawDiskHistory();
                return;
            }

            App.MarkSensorServiceConnected();
            ServiceState.Text = "LIVE · LOCAL";
            ServiceDot.Fill = new SolidColorBrush(Color.FromArgb(255, 73, 227, 193));
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var usedBytes = snapshot.MemoryTotalBytes - Math.Min(snapshot.MemoryTotalBytes, snapshot.MemoryAvailableBytes);
            double? memoryPercent = snapshot.MemoryTotalBytes > 0 ? usedBytes * 100d / snapshot.MemoryTotalBytes : null;
            double? commitPercent = snapshot.MemoryCommitLimitBytes is { } commitLimit && commitLimit > 0 && snapshot.MemoryCommittedBytes is { } committed
                ? Math.Clamp(committed * 100d / commitLimit, 0, 100)
                : null;
            _cpuGauge.SetValue(snapshot.CpuPercent);
            _memoryGauge.SetValue(memoryPercent);
            _commitGauge.SetMetric(commitPercent, commitPercent is { } commitValue ? $"{commitValue:0}%" : null);
            MemorySummary.Text = $"Physical memory · {FormatBytes(usedBytes)} used · {FormatBytes(snapshot.MemoryAvailableBytes)} available · {FormatBytes(snapshot.MemoryTotalBytes)} total";
            CommitSummary.Text = snapshot.MemoryCommittedBytes is { } committedBytes && snapshot.MemoryCommitLimitBytes is { } limitBytes
                ? $"System commit · {FormatBytes(committedBytes)} committed of {FormatBytes(limitBytes)} limit"
                : "System-wide commit limit unavailable";
            ProcessCount.Text = snapshot.ProcessCount.ToString("N0");
            UptimeValue.Text = FormatUptime(TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64)));
            StatusHeadline.Text = $"Live system sample · captured {captured:HH:mm:ss}";
            var network = await _networkClient.TryGetSnapshotAsync();
            var activeInterfaces = network?.Interfaces.Where(row => row.Status == "Up").ToArray() ?? [];
            var receive = network is null ? null : SumRates(activeInterfaces.Select(row => row.ReceiveBytesPerSecond));
            var send = network is null ? null : SumRates(activeInterfaces.Select(row => row.SendBytesPerSecond));
            var diskRead = snapshot.DiskReadBytesPerSecond;
            var diskWrite = snapshot.DiskWriteBytesPerSecond;
            ConnectionCount.Text = network?.TotalConnectionCount.ToString("N0") ?? "—";
            StatusDescription.Text = network is null
                ? "CPU/memory, commit, volume, and physical-disk readings are local. Adapter rates and connection totals are unavailable in this sample."
                : "CPU, memory, commit, volume, physical-disk throughput, adapter rates, and process inventory update locally every three seconds. Missing measurements remain unknown.";
            DiskIoSummary.Text = diskRead is { } readBytes && diskWrite is { } writeBytes
                ? $"All physical disks · read {FormatRate(readBytes)} · write {FormatRate(writeBytes)}"
                : "All physical disks · Windows counters are warming up or unavailable";

            _history.Enqueue(new PerformanceSample(snapshot.CapturedAtUtc, snapshot.CpuPercent, memoryPercent, commitPercent,
                snapshot.MemoryCommittedBytes, snapshot.MemoryCommitLimitBytes, receive, send, diskRead, diskWrite));
            TrimHistory();
            UpdateRateGauges(receive, send);
            UpdateDiskGauges(diskRead, diskWrite);
            DrawHistory();
            DrawNetworkHistory();
            DrawDiskHistory();

            var rows = snapshot.TopProcesses.Take(10).ToArray();
            var largest = rows.Length == 0 ? 0 : rows.Max(process => process.WorkingSetBytes);
            var processRows = rows.Select(process => new PerformanceProcessRow(process.ProcessId, process.Name,
                $"PID {process.ProcessId} · {FormatBytes(process.WorkingSetBytes)} · {process.ThreadCount:N0} threads · CPU {FormatCpu(process.CpuPercent)}",
                largest > 0 ? Math.Clamp(process.WorkingSetBytes * 100d / largest, 0, 100) : 0)).ToArray();
            CollectionReconciler.Apply(Processes, processRows, row => row.ProcessId, (current, incoming) =>
            {
                current.Name = incoming.Name;
                current.Detail = incoming.Detail;
                current.MemoryShare = incoming.MemoryShare;
            });
            ProcessWindowLabel.Text = $"TOP {rows.Length:N0} · {snapshot.TopProcesses.Count:N0} AVAILABLE";
        }
        catch (Exception exception)
        {
            ServiceState.Text = "SAMPLE UNAVAILABLE";
            ServiceDot.Fill = new SolidColorBrush(Color.FromArgb(255, 255, 180, 85));
            StatusHeadline.Text = "Performance sample could not be read · values cleared";
            StatusDescription.Text = exception.Message.Length > 240 ? exception.Message[..240] : exception.Message;
            _cpuGauge.SetValue(null);
            _memoryGauge.SetValue(null);
            _commitGauge.SetMetric(null, null);
            _receiveGauge.SetMetric(null, null);
            _sendGauge.SetMetric(null, null);
            _diskReadGauge.SetMetric(null, null);
            _diskWriteGauge.SetMetric(null, null);
            MemorySummary.Text = "Physical memory totals are unavailable in this sample";
            CommitSummary.Text = "System commit counters unavailable in this sample";
            DiskIoSummary.Text = "Physical disk counters unavailable in this sample";
            ProcessCount.Text = "—";
            ConnectionCount.Text = "—";
            UptimeValue.Text = "—";
            CollectionReconciler.Apply(Processes, Array.Empty<PerformanceProcessRow>(), row => row.ProcessId, (_, _) => { });
            _history.Enqueue(new PerformanceSample(DateTimeOffset.UtcNow, null, null, null, null, null, null, null, null, null));
            TrimHistory();
            DrawHistory();
            DrawNetworkHistory();
            DrawDiskHistory();
        }
        finally
        {
            _requestInFlight = false;
        }
    }

    private static string FormatBytes(ulong bytes)
    {
        double value = bytes;
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return unit == 0 ? $"{value:0} {units[unit]}" : $"{value:0.0} {units[unit]}";
    }

    private static string FormatBytes(long bytes) => FormatBytes((ulong)Math.Max(0, bytes));

    private static long? SumRates(IEnumerable<long?> values)
    {
        var known = values.Where(value => value.HasValue).Select(value => value!.Value).ToArray();
        if (known.Length == 0) return null;
        return known.Aggregate(0L, (sum, value) => sum > long.MaxValue - value ? long.MaxValue : sum + value);
    }

    private static string FormatRate(long bytesPerSecond) => $"{FormatBytes(bytesPerSecond)}/s";

    private static string FormatCpu(double? percent) => percent is { } value ? $"{value:0.0}%" : "—";

    private static string FormatUptime(TimeSpan uptime) => uptime.TotalDays >= 1
        ? $"{(int)uptime.TotalDays}d {uptime.Hours:00}:{uptime.Minutes:00}"
        : $"{uptime.Hours:00}:{uptime.Minutes:00}:{uptime.Seconds:00}";

    private static SystemVolumeReading ReadSystemVolume()
    {
        try
        {
            var root = System.IO.Path.GetPathRoot(Environment.SystemDirectory);
            if (string.IsNullOrWhiteSpace(root)) throw new IOException("Windows system-volume path is unavailable.");
            var drive = new DriveInfo(root);
            if (!drive.IsReady || drive.TotalSize <= 0) throw new IOException("Windows system volume is not ready.");
            var available = (ulong)Math.Max(0, drive.AvailableFreeSpace);
            var total = (ulong)drive.TotalSize;
            var used = total - Math.Min(total, available);
            var percent = used * 100d / total;
            return new SystemVolumeReading(percent, $"{percent:0}%", $"{drive.Name} · {percent:0}%",
                $"{FormatBytes(used)} used · {FormatBytes(available)} free of {FormatBytes(total)}");
        }
        catch
        {
            return new SystemVolumeReading(null, null, "Unavailable", "System volume could not be read");
        }
    }

    private void UpdateRateGauges(long? receive, long? send)
    {
        var recentPeak = _history.SelectMany(sample => new[] { sample.Receive, sample.Send })
            .Where(rate => rate.HasValue).Select(rate => (double)rate!.Value).DefaultIfEmpty(0).Max();
        var scale = Math.Max(1024 * 1024d, recentPeak);
        _receiveGauge.SetMetric(receive is { } rx ? Math.Clamp(rx * 100d / scale, 0, 100) : null,
            receive is { } receiveValue ? FormatRate(receiveValue) : null);
        _sendGauge.SetMetric(send is { } tx ? Math.Clamp(tx * 100d / scale, 0, 100) : null,
            send is { } sendValue ? FormatRate(sendValue) : null);
        NetworkChartScale.Text = recentPeak > 0
            ? $"Recent peak {FormatRate((long)Math.Min(recentPeak, long.MaxValue))} · gauge rings scale to the rolling 2-minute peak"
            : "Waiting for two adapter samples";
    }

    private void UpdateDiskGauges(long? read, long? write)
    {
        var recentPeak = _history.SelectMany(sample => new[] { sample.DiskRead, sample.DiskWrite })
            .Where(rate => rate.HasValue).Select(rate => (double)rate!.Value).DefaultIfEmpty(0).Max();
        var scale = Math.Max(1024 * 1024d, recentPeak);
        _diskReadGauge.SetMetric(read is { } rx ? Math.Clamp(rx * 100d / scale, 0, 100) : null,
            read is { } readValue ? FormatRate(readValue) : null);
        _diskWriteGauge.SetMetric(write is { } tx ? Math.Clamp(tx * 100d / scale, 0, 100) : null,
            write is { } writeValue ? FormatRate(writeValue) : null);
        DiskChartScale.Text = recentPeak > 0
            ? $"Recent peak {FormatRate((long)Math.Min(recentPeak, long.MaxValue))} · gauge rings scale to the rolling 2-minute peak"
            : "Waiting for valid PhysicalDisk counter samples";
    }

    private void TrimHistory()
    {
        while (_history.Count > HistoryLimit) _history.Dequeue();
    }

    private void HistoryHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawHistory();

    private void NetworkHistoryHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawNetworkHistory();

    private void DiskHistoryHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawDiskHistory();

    private void DrawHistory()
    {
        if (HistoryChart is null) return;
        HistoryChart.Children.Clear();
        var width = HistoryChart.ActualWidth;
        var height = HistoryChart.ActualHeight;
        if (width <= 1 || height <= 1) return;
        const double insetX = 38;
        const double insetY = 7;
        for (var level = 0; level <= 4; level++)
        {
            var y = insetY + (height - insetY * 2) * level / 4;
            HistoryChart.Children.Add(new Line
            {
                X1 = insetX, X2 = width - 8, Y1 = y, Y2 = y,
                Stroke = new SolidColorBrush(Color.FromArgb(38, 190, 220, 242)), StrokeThickness = 1
            });
            var label = new TextBlock
            {
                Text = $"{100 - level * 25}%", Width = 31, Height = 14,
                FontSize = 9, Foreground = new SolidColorBrush(Color.FromArgb(190, 164, 184, 199)),
                HorizontalTextAlignment = Microsoft.UI.Xaml.TextAlignment.Right
            };
            HistoryChart.Children.Add(label);
            Canvas.SetLeft(label, 0);
            Canvas.SetTop(label, Math.Clamp(y - 7, 0, Math.Max(0, height - 14)));
        }
        var samples = _history.ToArray();
        DrawSeries(samples.Select(sample => sample.Cpu).ToArray(), width, height, insetX, insetY, Color.FromArgb(255, 80, 219, 241));
        DrawSeries(samples.Select(sample => sample.Memory).ToArray(), width, height, insetX, insetY, Color.FromArgb(255, 180, 122, 248));
        DrawSeries(samples.Select(sample => sample.CommitPercent).ToArray(), width, height, insetX, insetY, Color.FromArgb(255, 255, 174, 92));
        ExportButton.IsEnabled = samples.Length > 0 && !_exportInFlight;
        HistoryEmpty.Visibility = samples.Any(sample => sample.Cpu.HasValue || sample.Memory.HasValue || sample.CommitPercent.HasValue)
            ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;
    }

    private void DrawNetworkHistory()
    {
        if (NetworkHistoryChart is null) return;
        NetworkHistoryChart.Children.Clear();
        var width = NetworkHistoryChart.ActualWidth;
        var height = NetworkHistoryChart.ActualHeight;
        if (width <= 1 || height <= 1) return;
        var samples = _history.ToArray();
        var peak = samples.SelectMany(sample => new[] { sample.Receive, sample.Send })
            .Where(rate => rate.HasValue).Select(rate => (double)rate!.Value).DefaultIfEmpty(0).Max();
        var scale = Math.Max(1024, peak);
        const double insetX = 60;
        const double insetY = 6;
        for (var level = 0; level <= 4; level++)
        {
            var y = insetY + (height - insetY * 2) * level / 4;
            var guide = new Line { X1 = insetX, X2 = width - 8, Y1 = y, Y2 = y, Stroke = new SolidColorBrush(Color.FromArgb(36, 190, 220, 242)), StrokeThickness = 1 };
            NetworkHistoryChart.Children.Add(guide);
            var label = new TextBlock { Text = FormatRate((long)Math.Min(scale * (4 - level) / 4d, long.MaxValue)), Width = 54, Height = 12, FontSize = 8, Foreground = new SolidColorBrush(Color.FromArgb(170, 164, 184, 199)), HorizontalTextAlignment = Microsoft.UI.Xaml.TextAlignment.Right };
            NetworkHistoryChart.Children.Add(label);
            Canvas.SetLeft(label, 0);
            Canvas.SetTop(label, Math.Clamp(y - 6, 0, Math.Max(0, height - 12)));
        }
        DrawRateSeries(NetworkHistoryChart, samples.Select(sample => sample.Receive).ToArray(), width, height, scale, insetX, insetY, Color.FromArgb(255, 80, 219, 241));
        DrawRateSeries(NetworkHistoryChart, samples.Select(sample => sample.Send).ToArray(), width, height, scale, insetX, insetY, Color.FromArgb(255, 180, 122, 248));
    }

    private void DrawDiskHistory()
    {
        if (DiskHistoryChart is null) return;
        DiskHistoryChart.Children.Clear();
        var width = DiskHistoryChart.ActualWidth;
        var height = DiskHistoryChart.ActualHeight;
        if (width <= 1 || height <= 1) return;
        var samples = _history.ToArray();
        var peak = samples.SelectMany(sample => new[] { sample.DiskRead, sample.DiskWrite })
            .Where(rate => rate.HasValue).Select(rate => (double)rate!.Value).DefaultIfEmpty(0).Max();
        var scale = Math.Max(1024, peak);
        const double insetX = 60;
        const double insetY = 6;
        for (var level = 0; level <= 4; level++)
        {
            var y = insetY + (height - insetY * 2) * level / 4;
            DiskHistoryChart.Children.Add(new Line { X1 = insetX, X2 = width - 8, Y1 = y, Y2 = y, Stroke = new SolidColorBrush(Color.FromArgb(36, 190, 220, 242)), StrokeThickness = 1 });
            var label = new TextBlock { Text = FormatRate((long)Math.Min(scale * (4 - level) / 4d, long.MaxValue)), Width = 54, Height = 12, FontSize = 8, Foreground = new SolidColorBrush(Color.FromArgb(170, 164, 184, 199)), HorizontalTextAlignment = Microsoft.UI.Xaml.TextAlignment.Right };
            DiskHistoryChart.Children.Add(label);
            Canvas.SetLeft(label, 0);
            Canvas.SetTop(label, Math.Clamp(y - 6, 0, Math.Max(0, height - 12)));
        }
        DrawRateSeries(DiskHistoryChart, samples.Select(sample => sample.DiskRead).ToArray(), width, height, scale, insetX, insetY, Color.FromArgb(255, 255, 174, 92));
        DrawRateSeries(DiskHistoryChart, samples.Select(sample => sample.DiskWrite).ToArray(), width, height, scale, insetX, insetY, Color.FromArgb(255, 180, 122, 248));
    }

    private void DrawRateSeries(Canvas chart, long?[] values, double width, double height, double scale, double insetX, double insetY, Color color)
    {
        var segment = new List<Point>();
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] is not { } value) { AddSegment(); continue; }
            var x = insetX + (width - insetX - 8) * index / Math.Max(1, values.Length - 1);
            var y = insetY + (height - insetY * 2) * (1 - Math.Clamp(value / scale, 0, 1));
            segment.Add(new Point(x, y));
        }
        AddSegment();

        void AddSegment()
        {
            if (segment.Count >= 2)
            {
                var glow = new PointCollection();
                var crisp = new PointCollection();
                foreach (var point in segment) { glow.Add(point); crisp.Add(point); }
                chart.Children.Add(new Polyline { Points = glow, Stroke = new SolidColorBrush(Color.FromArgb(28, color.R, color.G, color.B)), StrokeThickness = 8, StrokeLineJoin = PenLineJoin.Round });
                chart.Children.Add(new Polyline { Points = crisp, Stroke = new SolidColorBrush(color), StrokeThickness = 2, StrokeLineJoin = PenLineJoin.Round });
            }
            if (segment.Count > 0 && values.Length > 0 && segment[^1].X >= width - 8.1)
            {
                AddMarker(segment[^1], 11, Color.FromArgb(38, color.R, color.G, color.B));
                AddMarker(segment[^1], 4, color);
            }
            else if (segment.Count == 1) AddMarker(segment[0], 4, color);
            segment.Clear();
        }

        void AddMarker(Point point, double size, Color fill)
        {
            var marker = new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(fill) };
            chart.Children.Add(marker);
            Canvas.SetLeft(marker, point.X - size / 2);
            Canvas.SetTop(marker, point.Y - size / 2);
        }
    }

    private void DrawSeries(double?[] values, double width, double height, double insetX, double insetY, Color color)
    {
        var segment = new List<Point>();
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] is not { } value) { AddSegment(); continue; }
            var x = insetX + (width - insetX - 8) * index / Math.Max(1, values.Length - 1);
            var y = insetY + (height - insetY * 2) * (1 - Math.Clamp(value, 0, 100) / 100d);
            segment.Add(new Point(x, y));
        }
        AddSegment();

        void AddSegment()
        {
            if (segment.Count >= 2)
            {
                var glowPoints = new PointCollection();
                foreach (var point in segment) glowPoints.Add(point);
                var crispPoints = new PointCollection();
                foreach (var point in segment) crispPoints.Add(point);
                HistoryChart.Children.Add(new Polyline { Points = glowPoints, Stroke = new SolidColorBrush(Color.FromArgb(28, color.R, color.G, color.B)), StrokeThickness = 8, StrokeLineJoin = PenLineJoin.Round });
                HistoryChart.Children.Add(new Polyline { Points = crispPoints, Stroke = new SolidColorBrush(color), StrokeThickness = 2, StrokeLineJoin = PenLineJoin.Round });
            }
            if (segment.Count > 0 && values.Length > 0 && segment[^1].X >= width - 8.1)
            {
                var point = segment[^1];
                AddMarker(point, 12, Color.FromArgb(40, color.R, color.G, color.B));
                AddMarker(point, 5, color);
            }
            else if (segment.Count == 1)
            {
                var point = segment[0];
                AddMarker(point, 5, color);
            }
            segment.Clear();
        }

        void AddMarker(Point point, double size, Color fill)
        {
            var marker = new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(fill) };
            HistoryChart.Children.Add(marker);
            Canvas.SetLeft(marker, point.X - size / 2);
            Canvas.SetTop(marker, point.Y - size / 2);
        }
    }

    private sealed record PerformanceSample(DateTimeOffset CapturedAtUtc, double? Cpu, double? Memory, double? CommitPercent,
        ulong? CommittedBytes, ulong? CommitLimitBytes, long? Receive, long? Send, long? DiskRead, long? DiskWrite);
    private sealed record SystemVolumeReading(double? UsagePercent, string? DisplayValue, string Value, string Detail);
}

public sealed class PerformanceProcessRow : ObservableRow
{
    private string _name = "";
    private string _detail = "";
    private double _memoryShare;

    public PerformanceProcessRow() { }
    public PerformanceProcessRow(int processId, string name, string detail, double memoryShare) =>
        (ProcessId, _name, _detail, _memoryShare) = (processId, name, detail, memoryShare);

    public int ProcessId { get; set; }
    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string Detail { get => _detail; set => SetProperty(ref _detail, value); }
    public double MemoryShare { get => _memoryShare; set => SetProperty(ref _memoryShare, value); }
}
