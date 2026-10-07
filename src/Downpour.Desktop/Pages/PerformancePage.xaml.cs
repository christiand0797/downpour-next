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
    private readonly CircularGauge _pageFileGauge;
    private readonly CircularGauge _receiveGauge;
    private readonly CircularGauge _sendGauge;
    private readonly CircularGauge _diskReadGauge;
    private readonly CircularGauge _diskWriteGauge;
    private readonly CircularGauge _gpuGauge;
    private readonly CircularGauge _gpuMemoryGauge;
    private readonly CircularGauge _thermalGauge;
    private readonly List<CircularGauge> _perCoreGauges = [];
    private bool _requestInFlight;
    private bool _samplingPaused;
    private bool _exportInFlight;
    private ChartGrid? _performanceGrid;
    private ChartGrid? _networkGrid;
    private ChartGrid? _diskGrid;
    private ChartGrid? _perCoreHistoryGrid;
    private ChartGrid? _perDiskHistoryGrid;
    private ChartLineRenderer? _cpuSeries;
    private ChartLineRenderer? _memorySeries;
    private ChartLineRenderer? _commitSeries;
    private ChartLineRenderer? _receiveSeries;
    private ChartLineRenderer? _sendSeries;
    private ChartLineRenderer? _diskReadSeries;
    private ChartLineRenderer? _diskWriteSeries;
    private readonly List<ChartLineRenderer> _perCoreHistorySeries = [];
    private readonly List<Queue<double?>> _perCoreHistory = [];
    private readonly List<CircularGauge> _perDiskReadGauges = [];
    private readonly List<CircularGauge> _perDiskWriteGauges = [];
    private readonly List<Queue<double?>> _perDiskReadHistory = [];
    private readonly List<Queue<double?>> _perDiskWriteHistory = [];
    private readonly List<ChartLineRenderer> _perDiskReadHistorySeries = [];
    private readonly List<ChartLineRenderer> _perDiskWriteHistorySeries = [];
    private readonly Dictionary<int, Queue<double?>> _processCpuHistory = [];
    private readonly Dictionary<int, string> _processNames = [];
    private int _processSortMode = 0; // 0=Memory, 1=CPU, 2=PID, 3=Name
    private int? _selectedProcessPid = null;
    private ChartGrid? _processCpuHistoryGrid;
    private ChartLineRenderer? _processCpuHistorySeries;

    public ObservableCollection<PerformanceProcessRow> Processes { get; } = [];

    public PerformancePage()
    {
        InitializeComponent();
        _cpuGauge = new CircularGauge("CPU", Color.FromArgb(255, 74, 220, 243));
        _memoryGauge = new CircularGauge("MEMORY", Color.FromArgb(255, 178, 121, 248));
        _commitGauge = new CircularGauge("COMMIT", Color.FromArgb(255, 255, 174, 92));
        _diskGauge = new CircularGauge("OS DISK", Color.FromArgb(255, 255, 176, 94));
        _pageFileGauge = new CircularGauge("PAGEFILE", Color.FromArgb(255, 180, 122, 248));
        _receiveGauge = new CircularGauge("RX / s", Color.FromArgb(255, 80, 219, 241));
        _sendGauge = new CircularGauge("TX / s", Color.FromArgb(255, 180, 122, 248));
        _diskReadGauge = new CircularGauge("DISK READ", Color.FromArgb(255, 255, 174, 92));
        _diskWriteGauge = new CircularGauge("DISK WRITE", Color.FromArgb(255, 180, 122, 248));
        AddGauge(_cpuGauge, 0, 0);
        AddGauge(_memoryGauge, 1, 0);
        AddGauge(_diskGauge, 2, 0);
        AddGauge(_pageFileGauge, 0, 1);
        AddGauge(_receiveGauge, 1, 1);
        AddGauge(_sendGauge, 2, 1);
        AddGauge(_commitGauge, 0, 2);
        AddGauge(_diskReadGauge, 1, 2);
        AddGauge(_diskWriteGauge, 2, 2);
        _gpuGauge = new CircularGauge("GPU", Color.FromArgb(255, 80, 240, 120));
        _gpuMemoryGauge = new CircularGauge("GPU MEMORY", Color.FromArgb(255, 80, 240, 120));
        _thermalGauge = new CircularGauge("THERMAL ZONE", Color.FromArgb(255, 255, 100, 100));
        AddGauge(_gpuGauge, 0, 3);
        AddGauge(_gpuMemoryGauge, 1, 3);
        AddGauge(_thermalGauge, 2, 3);

        // Initialize per-core CPU gauges (up to 16 cores)
        var coreCount = Environment.ProcessorCount;
        for (int i = 0; i < coreCount; i++)
        {
            var gauge = new CircularGauge($"CORE {i}", Color.FromArgb(255, 80, 219, 241));
            _perCoreGauges.Add(gauge);
        }

        // Add per-core gauges to a 4-column grid with as many rows as the machine needs (laptops can exceed 16 threads).
        while (PerCoreGaugeHost.ColumnDefinitions.Count < 4)
            PerCoreGaugeHost.ColumnDefinitions.Add(new ColumnDefinition { Width = new Microsoft.UI.Xaml.GridLength(1, Microsoft.UI.Xaml.GridUnitType.Star) });
        while (PerCoreGaugeHost.RowDefinitions.Count < (_perCoreGauges.Count + 3) / 4)
            PerCoreGaugeHost.RowDefinitions.Add(new RowDefinition { Height = Microsoft.UI.Xaml.GridLength.Auto });
        for (int i = 0; i < _perCoreGauges.Count; i++)
        {
            var col = i % 4;
            var row = i / 4;
            PerCoreGaugeHost.Children.Add(_perCoreGauges[i]);
            Grid.SetColumn(_perCoreGauges[i], col);
            Grid.SetRow(_perCoreGauges[i], row);
        }

        // Initialize per-core history queues and colors
        var coreColors = new[]
        {
            Color.FromArgb(255, 80, 219, 241),   // cyan
            Color.FromArgb(255, 180, 122, 248),  // purple
            Color.FromArgb(255, 255, 174, 92),   // amber
            Color.FromArgb(255, 80, 240, 120),   // green
            Color.FromArgb(255, 255, 100, 100),  // red
            Color.FromArgb(255, 100, 200, 255),  // blue
            Color.FromArgb(255, 255, 150, 200),  // pink
            Color.FromArgb(255, 150, 255, 150),  // light green
            Color.FromArgb(255, 200, 150, 255),  // light purple
            Color.FromArgb(255, 255, 200, 100),  // orange
            Color.FromArgb(255, 100, 255, 255),  // light cyan
            Color.FromArgb(255, 255, 255, 150),  // yellow
            Color.FromArgb(255, 180, 180, 255),  // lavender
            Color.FromArgb(255, 255, 180, 180),  // peach
            Color.FromArgb(255, 180, 255, 200),  // mint
            Color.FromArgb(255, 220, 220, 220),  // gray
        };
        for (int i = 0; i < _perCoreGauges.Count; i++)
        {
            _perCoreHistory.Add(new Queue<double?>());
            var series = new ChartLineRenderer(PerCoreHistoryChart, coreColors[i % coreColors.Length]);
            _perCoreHistorySeries.Add(series);
        }

        CpuCount.Text = Environment.ProcessorCount.ToString("N0");
        CpuDetail.Text = "Logical processors · Windows reports topology only";
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(3);
        _timer.IsRepeating = true;
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        ProcessSortCombo.SelectedIndex = 0; // Default to Memory sort
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

    private void ProcessSortCombo_SelectionChanged(object sender, Microsoft.UI.Xaml.Controls.SelectionChangedEventArgs e)
    {
        if (ProcessSortCombo?.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var mode)) return;
        _processSortMode = mode;
        _ = RefreshAsync(); // Re-render with new sort
    }

    private void ProcessFilterBox_TextChanged(object sender, Microsoft.UI.Xaml.Controls.TextChangedEventArgs e)
    {
        ApplyProcessFilter();
    }

    private void ApplyProcessFilter()
    {
        var query = ProcessFilterBox?.Text?.Trim() ?? "";
        int visibleCount = 0;
        foreach (var row in Processes)
        {
            bool matches = query.Length == 0 ||
                row.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Detail.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.ProcessId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase);
            row.Visibility = matches ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
            if (matches) visibleCount++;
        }
        if (ProcessWindowLabel is not null && query.Length > 0)
        {
            var totalRows = Processes.Count;
            ProcessWindowLabel.Text = $"SHOWING {visibleCount:N0} OF {totalRows:N0} (FILTERED)";
        }
    }

    private void ProcessList_SelectionChanged(object sender, Microsoft.UI.Xaml.Controls.SelectionChangedEventArgs e)
    {
        var hasSelection = ProcessList?.SelectedItem is PerformanceProcessRow;
        if (OpenLocationButton is not null) OpenLocationButton.IsEnabled = hasSelection;
        if (EndProcessButton is not null) EndProcessButton.IsEnabled = hasSelection;
        if (ProcessList?.SelectedItem is not PerformanceProcessRow row) return;
        _selectedProcessPid = row.ProcessId;
        if (_processNames.TryGetValue(row.ProcessId, out var name))
        {
            ProcessCpuHistoryTitle.Text = $"{name} (PID {row.ProcessId}) · CPU history";
        }
        DrawProcessCpuHistory();
    }

    private void IntervalCombo_SelectionChanged(object sender, Microsoft.UI.Xaml.Controls.SelectionChangedEventArgs e)
    {
        // The XAML pre-selects "3 sec", so WinUI raises this during InitializeComponent(), before the timer exists.
        // Touching _timer then threw a NullReferenceException that crashed the app when Performance was opened.
        if (_timer is null || PauseButton is null) return;
        if (IntervalCombo?.SelectedItem is not ComboBoxItem item) return;
        if (!int.TryParse(item.Tag?.ToString(), out var seconds)) return;
        _timer.Interval = TimeSpan.FromSeconds(seconds);
        PauseButton.Content = _samplingPaused ? "▶  Resume" : $"Ⅱ  Pause ({seconds}s)";
        ToolTipService.SetToolTip(PauseButton, _samplingPaused
            ? "Resume automatic sampling."
            : $"Pause automatic {seconds}-second sampling.");
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
                _pageFileGauge.SetMetric(null, null);
                _receiveGauge.SetMetric(null, null);
                _sendGauge.SetMetric(null, null);
                _diskReadGauge.SetMetric(null, null);
                _diskWriteGauge.SetMetric(null, null);
                MemorySummary.Text = "Physical memory totals are unavailable with the sensor offline";
                CommitSummary.Text = "System commit counters unavailable";
                PageFileSummary.Text = "Pagefile counters unavailable";
                DiskIoSummary.Text = "Physical disk counters unavailable with the sensor offline";
                ShowGpuAndThermal(null);
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

            // Update per-core CPU gauges
            if (snapshot.PerCoreCpuPercent is { } perCore)
            {
                for (int i = 0; i < _perCoreGauges.Count && i < perCore.Count; i++)
                {
                    _perCoreGauges[i].SetValue(perCore[i]);
                }
                // Clear any extra gauges if fewer cores reported
                for (int i = perCore.Count; i < _perCoreGauges.Count; i++)
                {
                    _perCoreGauges[i].SetValue(null);
                }
                PerCoreCpuDetail.Text = $"Per-core CPU utilization from Windows performance counters ({perCore.Count} cores reported)";
            }
            else
            {
                foreach (var gauge in _perCoreGauges)
                {
                    gauge.SetValue(null);
                }
                PerCoreCpuDetail.Text = "Per-core CPU utilization from Windows performance counters (unavailable)";
            }

            MemorySummary.Text = $"Physical memory · {FormatBytes(usedBytes)} used · {FormatBytes(snapshot.MemoryAvailableBytes)} available · {FormatBytes(snapshot.MemoryTotalBytes)} total";
            CommitSummary.Text = snapshot.MemoryCommittedBytes is { } committedBytes && snapshot.MemoryCommitLimitBytes is { } limitBytes
                ? $"System commit · {FormatBytes(committedBytes)} committed of {FormatBytes(limitBytes)} limit"
                : "System-wide commit limit unavailable";
            // Pagefile
            if (snapshot.PageFileTotalBytes is { } pageFileTotal && pageFileTotal > 0 && snapshot.PageFileAvailableBytes is { } pageFileAvail)
            {
                var pageFileUsed = pageFileTotal - Math.Min(pageFileTotal, pageFileAvail);
                var pageFilePercent = pageFileUsed * 100d / pageFileTotal;
                _pageFileGauge.SetMetric(Math.Clamp(pageFilePercent, 0, 100), $"{pageFilePercent:0}%");
                PageFileSummary.Text = $"Pagefile · {FormatBytes(pageFileUsed)} used · {FormatBytes(pageFileAvail)} available · {FormatBytes(pageFileTotal)} total";
            }
            else
            {
                _pageFileGauge.SetMetric(null, null);
                PageFileSummary.Text = "Pagefile counters unavailable";
            }
            ShowGpuAndThermal(snapshot);
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

            // Initialize per-disk gauges on first snapshot with physical disks
            if (snapshot.PhysicalDisks is { } physicalDisks && physicalDisks.Count > 0 && _perDiskReadGauges.Count == 0)
            {
                InitializePerDiskGauges(physicalDisks);
            }

            // Update per-disk gauges
            if (snapshot.PhysicalDisks is { } disks)
            {
                UpdatePerDiskGauges(disks);
            }

            _history.Enqueue(new PerformanceSample(snapshot.CapturedAtUtc, snapshot.CpuPercent, memoryPercent, commitPercent,
                snapshot.MemoryCommittedBytes, snapshot.MemoryCommitLimitBytes, receive, send, diskRead, diskWrite));
            TrimHistory();

            // Record per-core CPU history
            var perCoreHistoryData = snapshot.PerCoreCpuPercent;
            if (perCoreHistoryData is { } coreValues)
            {
                for (int i = 0; i < _perCoreHistory.Count && i < coreValues.Count; i++)
                {
                    var queue = _perCoreHistory[i];
                    queue.Enqueue(coreValues[i]);
                    while (queue.Count > HistoryLimit) queue.Dequeue();
                }
            }
            else
            {
                for (int i = 0; i < _perCoreHistory.Count; i++)
                {
                    var queue = _perCoreHistory[i];
                    queue.Enqueue(null);
                    while (queue.Count > HistoryLimit) queue.Dequeue();
                }
            }

            UpdateRateGauges(receive, send);
            UpdateDiskGauges(diskRead, diskWrite);
            DrawHistory();
            DrawNetworkHistory();
            DrawDiskHistory();
            DrawPerCoreHistory();
            DrawPerDiskHistory();
            DrawProcessCpuHistory();

            var topProcesses = snapshot.TopProcesses.Take(50).ToArray(); // Get more for sorting
            var largest = topProcesses.Length == 0 ? 0 : topProcesses.Max(process => process.WorkingSetBytes);

            // Track process CPU history
            foreach (var process in topProcesses)
            {
                if (!_processCpuHistory.ContainsKey(process.ProcessId))
                {
                    _processCpuHistory[process.ProcessId] = new Queue<double?>();
                }
                var queue = _processCpuHistory[process.ProcessId];
                queue.Enqueue(process.CpuPercent);
                while (queue.Count > HistoryLimit) queue.Dequeue();
                _processNames[process.ProcessId] = process.Name;
            }

            // Sort processes based on selected mode
            var sortedProcesses = _processSortMode switch
            {
                1 => topProcesses.OrderByDescending(p => p.CpuPercent ?? -1).ToArray(), // CPU
                2 => topProcesses.OrderBy(p => p.ProcessId).ToArray(), // PID
                3 => topProcesses.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToArray(), // Name
                _ => topProcesses.OrderByDescending(p => p.WorkingSetBytes).ToArray(), // Memory (default)
            };

            var filterQuery = ProcessFilterBox?.Text?.Trim() ?? "";
            var showAll = filterQuery.Length > 0;
            var limit = showAll ? 50 : 10;
            var rows = sortedProcesses.Take(limit).ToArray();
            var processRows = rows.Select(process => new PerformanceProcessRow(process.ProcessId, process.Name,
                $"PID {process.ProcessId} · {FormatBytes(process.WorkingSetBytes)} · {process.ThreadCount:N0} threads · CPU {FormatCpu(process.CpuPercent)}",
                largest > 0 ? Math.Clamp(process.WorkingSetBytes * 100d / largest, 0, 100) : 0)).ToArray();
            CollectionReconciler.Apply(Processes, processRows, row => row.ProcessId, (current, incoming) =>
            {
                current.Name = incoming.Name;
                current.Detail = incoming.Detail;
                current.MemoryShare = incoming.MemoryShare;
            });
            var visibleCount = processRows.Count(r => r.Visibility == Microsoft.UI.Xaml.Visibility.Visible);
            ProcessWindowLabel.Text = filterQuery.Length > 0
                ? $"SHOWING {visibleCount:N0} OF {rows.Length:N0} (FILTERED) · {snapshot.TopProcesses.Count:N0} AVAILABLE"
                : $"TOP {rows.Length:N0} · {snapshot.TopProcesses.Count:N0} AVAILABLE";
        }
        catch (Exception exception)
        {
            ServiceState.Text = "SAMPLE UNAVAILABLE";
            ShowGpuAndThermal(null);
            ServiceDot.Fill = new SolidColorBrush(Color.FromArgb(255, 255, 180, 85));
            StatusHeadline.Text = "Performance sample could not be read · values cleared";
            StatusDescription.Text = exception.Message.Length > 240 ? exception.Message[..240] : exception.Message;
            _cpuGauge.SetValue(null);
            _memoryGauge.SetValue(null);
            _commitGauge.SetMetric(null, null);
            _pageFileGauge.SetMetric(null, null);
            _receiveGauge.SetMetric(null, null);
            _sendGauge.SetMetric(null, null);
            _diskReadGauge.SetMetric(null, null);
            _diskWriteGauge.SetMetric(null, null);
            MemorySummary.Text = "Physical memory totals are unavailable in this sample";
            CommitSummary.Text = "System commit counters unavailable in this sample";
            PageFileSummary.Text = "Pagefile counters unavailable";
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

    private void OpenLocation_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (ProcessList?.SelectedItem is not PerformanceProcessRow row) return;
        string? path = null;
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(row.ProcessId);
            path = process.MainModule?.FileName;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            ProcessActionStatus.Text = $"The program file of PID {row.ProcessId} cannot be read from this account (protected, elevated, or already exited).";
            return;
        }
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            ProcessActionStatus.Text = $"PID {row.ProcessId} has no program file that can be shown.";
            return;
        }
        // Documented shell API; no command line is run.
        ProcessActionStatus.Text = ShellSelect.Reveal(path) ? $"Showing {path}" : $"File Explorer could not show {path}.";
    }

    private async void EndProcess_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (ProcessList?.SelectedItem is not PerformanceProcessRow row) return;
        DateTimeOffset startTime;
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(row.ProcessId);
            startTime = process.StartTime.ToUniversalTime();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            ProcessActionStatus.Text = $"PID {row.ProcessId} is no longer running or its start time cannot be read.";
            return;
        }

        var client = new ProcessTerminationClient();
        var preview = await client.PreviewTerminateAsync(row.ProcessId, startTime);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await client.PreviewTerminateAsync(row.ProcessId, startTime);
        }
        if (preview is null) { ProcessActionStatus.Text = "The action broker is not reachable; ending processes needs the service this desktop started."; return; }
        if (!preview.Accepted || preview.Preview?.ConsentToken is null) { ProcessActionStatus.Text = preview.Message; return; }

        var p = preview.Preview;
        var dialog = new ContentDialog
        {
            Title = "End this process?",
            Content = new ScrollViewer
            {
                MaxHeight = 360,
                Content = new TextBlock
                {
                    TextWrapping = Microsoft.UI.Xaml.TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                    Text = $"{p.ProcessName} (PID {p.ProcessId})\n{p.ImagePath}\nStarted {p.StartTimeUtc.ToLocalTime():g}\n\n• {string.Join("\n• ", p.Risks)}",
                },
            },
            PrimaryButtonText = "End process",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) { ProcessActionStatus.Text = "Cancelled. Nothing was changed."; return; }

        var result = await client.TerminateAsync(row.ProcessId, startTime, p.ConsentToken);
        ProcessActionStatus.Text = result?.Message ?? "The action broker did not confirm the result.";
        await RefreshAsync();
    }

    /// <summary>GPU and thermal-zone gauges. Every value can be missing (no WDDM GPU counters, no ACPI thermal zones).</summary>
    private void ShowGpuAndThermal(SystemHealthSnapshot? snapshot)
    {
        _gpuGauge.SetMetric(snapshot?.GpuPercent, snapshot?.GpuPercent is { } gpu ? $"{gpu:0}%" : null);
        var dedicated = snapshot?.GpuDedicatedMemoryBytes;
        var shared = snapshot?.GpuSharedMemoryBytes;
        // Windows does not expose total GPU memory through these counters, so the ring stays empty and only usage is shown.
        _gpuMemoryGauge.SetMetric(null, dedicated is { } d ? FormatBytes(d) : null);
        GpuSummary.Text = snapshot is null ? "GPU counters unavailable with the sensor offline"
            : snapshot.GpuPercent is null && dedicated is null ? "GPU counters are warming up or unavailable on this PC"
            : $"GPU · busiest engine {(snapshot.GpuPercent is { } p ? $"{p:0}%" : "warming up")} · dedicated memory in use {(dedicated is { } dd ? FormatBytes(dd) : "unknown")} · shared {(shared is { } s ? FormatBytes(s) : "unknown")}";

        if (snapshot?.ThermalZoneCelsius is { } celsius)
        {
            _thermalGauge.SetMetric(Math.Clamp(celsius, 0, 100), $"{celsius:0} °C");
            ThermalSummary.Text = $"Thermal zone · {celsius:0.0} °C (hottest ACPI thermal zone reported by firmware; this is often a motherboard sensor, not the CPU die)";
        }
        else
        {
            _thermalGauge.SetMetric(null, null);
            ThermalSummary.Text = "Temperature unavailable · this PC's firmware exposes no ACPI thermal zones to Windows";
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
        var width = HistoryChart.ActualWidth;
        var height = HistoryChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;
        const double insetX = 38;
        const double insetY = 7;
        _performanceGrid ??= new ChartGrid(HistoryChart, insetX, insetY, 31, 14, 9,
            Color.FromArgb(38, 190, 220, 242), Color.FromArgb(190, 164, 184, 199));
        _cpuSeries ??= new ChartLineRenderer(HistoryChart, Color.FromArgb(255, 80, 219, 241));
        _memorySeries ??= new ChartLineRenderer(HistoryChart, Color.FromArgb(255, 180, 122, 248));
        _commitSeries ??= new ChartLineRenderer(HistoryChart, Color.FromArgb(255, 255, 174, 92));
        _performanceGrid.Update(width, height, ["100%", "75%", "50%", "25%", "0%"]);
        var samples = _history.ToArray();
        _cpuSeries.Update(MapSeries(samples.Select(sample => sample.Cpu).ToArray(), width, height, insetX, insetY), width - 8.1);
        _memorySeries.Update(MapSeries(samples.Select(sample => sample.Memory).ToArray(), width, height, insetX, insetY), width - 8.1);
        _commitSeries.Update(MapSeries(samples.Select(sample => sample.CommitPercent).ToArray(), width, height, insetX, insetY), width - 8.1);
        ExportButton.IsEnabled = samples.Length > 0 && !_exportInFlight;
        HistoryEmpty.Visibility = samples.Any(sample => sample.Cpu.HasValue || sample.Memory.HasValue || sample.CommitPercent.HasValue)
            ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;
    }

    private void DrawNetworkHistory()
    {
        if (NetworkHistoryChart is null) return;
        var width = NetworkHistoryChart.ActualWidth;
        var height = NetworkHistoryChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;
        var samples = _history.ToArray();
        var peak = samples.SelectMany(sample => new[] { sample.Receive, sample.Send })
            .Where(rate => rate.HasValue).Select(rate => (double)rate!.Value).DefaultIfEmpty(0).Max();
        var scale = Math.Max(1024, peak);
        const double insetX = 60;
        const double insetY = 6;
        _networkGrid ??= new ChartGrid(NetworkHistoryChart, insetX, insetY, 54, 12, 8,
            Color.FromArgb(36, 190, 220, 242), Color.FromArgb(170, 164, 184, 199));
        _receiveSeries ??= new ChartLineRenderer(NetworkHistoryChart, Color.FromArgb(255, 80, 219, 241));
        _sendSeries ??= new ChartLineRenderer(NetworkHistoryChart, Color.FromArgb(255, 180, 122, 248));
        _networkGrid.Update(width, height, Enumerable.Range(0, 5)
            .Select(level => FormatRate((long)Math.Min(scale * (4 - level) / 4d, long.MaxValue))).ToArray());
        _receiveSeries.Update(MapRateSeries(samples.Select(sample => sample.Receive).ToArray(), width, height, scale, insetX, insetY), width - 8.1);
        _sendSeries.Update(MapRateSeries(samples.Select(sample => sample.Send).ToArray(), width, height, scale, insetX, insetY), width - 8.1);
    }

    private void DrawDiskHistory()
    {
        if (DiskHistoryChart is null) return;
        var width = DiskHistoryChart.ActualWidth;
        var height = DiskHistoryChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;
        var samples = _history.ToArray();
        var peak = samples.SelectMany(sample => new[] { sample.DiskRead, sample.DiskWrite })
            .Where(rate => rate.HasValue).Select(rate => (double)rate!.Value).DefaultIfEmpty(0).Max();
        var scale = Math.Max(1024, peak);
        const double insetX = 60;
        const double insetY = 6;
        _diskGrid ??= new ChartGrid(DiskHistoryChart, insetX, insetY, 54, 12, 8,
            Color.FromArgb(36, 190, 220, 242), Color.FromArgb(170, 164, 184, 199));
        _diskReadSeries ??= new ChartLineRenderer(DiskHistoryChart, Color.FromArgb(255, 255, 174, 92));
        _diskWriteSeries ??= new ChartLineRenderer(DiskHistoryChart, Color.FromArgb(255, 180, 122, 248));
        _diskGrid.Update(width, height, Enumerable.Range(0, 5)
            .Select(level => FormatRate((long)Math.Min(scale * (4 - level) / 4d, long.MaxValue))).ToArray());
        _diskReadSeries.Update(MapRateSeries(samples.Select(sample => sample.DiskRead).ToArray(), width, height, scale, insetX, insetY), width - 8.1);
        _diskWriteSeries.Update(MapRateSeries(samples.Select(sample => sample.DiskWrite).ToArray(), width, height, scale, insetX, insetY), width - 8.1);
    }

    private static Point?[] MapRateSeries(long?[] values, double width, double height, double scale, double insetX, double insetY)
    {
        var points = new Point?[values.Length];
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] is not { } value) continue;
            var x = insetX + (width - insetX - 8) * index / Math.Max(1, values.Length - 1);
            var y = insetY + (height - insetY * 2) * (1 - Math.Clamp(value / scale, 0, 1));
            if (double.IsFinite(x) && double.IsFinite(y)) points[index] = new Point(x, y);
        }
        return points;
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

    private void DrawPerCoreHistory()
    {
        if (PerCoreHistoryChart is null) return;
        var width = PerCoreHistoryChart.ActualWidth;
        var height = PerCoreHistoryChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;

        const double insetX = 38;
        const double insetY = 7;
        _perCoreHistoryGrid ??= new ChartGrid(PerCoreHistoryChart, insetX, insetY, 31, 14, 9,
            Color.FromArgb(38, 190, 220, 242), Color.FromArgb(190, 164, 184, 199));
        _perCoreHistoryGrid.Update(width, height, ["100%", "75%", "50%", "25%", "0%"]);

        bool hasData = false;
        for (int i = 0; i < _perCoreHistory.Count; i++)
        {
            var queue = _perCoreHistory[i];
            var values = queue.ToArray();
            var points = MapSeries(values, width, height, insetX, insetY);
            if (i < _perCoreHistorySeries.Count)
            {
                _perCoreHistorySeries[i].Update(points, width - 8.1);
            }
            if (!hasData && values.Any(v => v.HasValue)) hasData = true;
        }
        if (PerCoreHistoryEmpty is not null)
        {
            PerCoreHistoryEmpty.Visibility = hasData
                ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;
        }
    }

    private void PerCoreHistoryHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawPerCoreHistory();

    private void InitializePerDiskGauges(IReadOnlyList<PhysicalDiskSnapshot> disks)
    {
        if (PerDiskGaugeHost is null || PerDiskHistoryChart is null) return;

        var diskColors = new[]
        {
            Color.FromArgb(255, 80, 219, 241),   // cyan
            Color.FromArgb(255, 180, 122, 248),  // purple
            Color.FromArgb(255, 255, 174, 92),   // amber
            Color.FromArgb(255, 80, 240, 120),   // green
            Color.FromArgb(255, 255, 100, 100),  // red
            Color.FromArgb(255, 100, 200, 255),  // blue
            Color.FromArgb(255, 255, 150, 200),  // pink
            Color.FromArgb(255, 150, 255, 150),  // light green
        };

        int diskIndex = 0;
        foreach (var disk in disks)
        {
            if (string.Equals(disk.InstanceName, "_Total", StringComparison.OrdinalIgnoreCase)) continue;

            var readGauge = new CircularGauge($"{disk.InstanceName} RD", diskColors[diskIndex % diskColors.Length]);
            var writeGauge = new CircularGauge($"{disk.InstanceName} WR", diskColors[diskIndex % diskColors.Length]);
            _perDiskReadGauges.Add(readGauge);
            _perDiskWriteGauges.Add(writeGauge);
            _perDiskReadHistory.Add(new Queue<double?>());
            _perDiskWriteHistory.Add(new Queue<double?>());

            var col = (diskIndex * 2) % 4;
            var row = (diskIndex * 2) / 4;
            PerDiskGaugeHost.Children.Add(readGauge);
            Grid.SetColumn(readGauge, col);
            Grid.SetRow(readGauge, row);
            PerDiskGaugeHost.Children.Add(writeGauge);
            Grid.SetColumn(writeGauge, col + 1);
            Grid.SetRow(writeGauge, row);

            var readSeries = new ChartLineRenderer(PerDiskHistoryChart, diskColors[diskIndex % diskColors.Length]);
            var writeSeries = new ChartLineRenderer(PerDiskHistoryChart, Color.FromArgb(255, 
                (byte)Math.Min(255, diskColors[diskIndex % diskColors.Length].R + 50),
                (byte)Math.Min(255, diskColors[diskIndex % diskColors.Length].G + 50),
                (byte)Math.Min(255, diskColors[diskIndex % diskColors.Length].B + 50)));
            _perDiskReadHistorySeries.Add(readSeries);
            _perDiskWriteHistorySeries.Add(writeSeries);

            diskIndex++;
        }
    }

    private void UpdatePerDiskGauges(IReadOnlyList<PhysicalDiskSnapshot> disks)
    {
        int diskIndex = 0;
        double? maxRead = null;
        double? maxWrite = null;

        // First pass: find max values for scaling
        foreach (var disk in disks)
        {
            if (string.Equals(disk.InstanceName, "_Total", StringComparison.OrdinalIgnoreCase)) continue;
            if (disk.ReadBytesPerSecond is { } r && (maxRead is null || r > maxRead)) maxRead = r;
            if (disk.WriteBytesPerSecond is { } w && (maxWrite is null || w > maxWrite)) maxWrite = w;
        }

        // Second pass: update gauges and record history
        foreach (var disk in disks)
        {
            if (string.Equals(disk.InstanceName, "_Total", StringComparison.OrdinalIgnoreCase)) continue;

            if (diskIndex < _perDiskReadGauges.Count)
            {
                double? readPercent = null;
                double? writePercent = null;

                if (maxRead.HasValue && maxRead > 0 && disk.ReadBytesPerSecond is { } readVal)
                {
                    readPercent = Math.Clamp(readVal * 100d / maxRead.Value, 0, 100);
                }
                if (maxWrite.HasValue && maxWrite > 0 && disk.WriteBytesPerSecond is { } writeVal)
                {
                    writePercent = Math.Clamp(writeVal * 100d / maxWrite.Value, 0, 100);
                }

                var readDisplay = disk.ReadBytesPerSecond is { } r ? FormatRate(r) : null;
                var writeDisplay = disk.WriteBytesPerSecond is { } w ? FormatRate(w) : null;

                _perDiskReadGauges[diskIndex].SetMetric(readPercent, readDisplay);
                _perDiskWriteGauges[diskIndex].SetMetric(writePercent, writeDisplay);

                // Record history
                _perDiskReadHistory[diskIndex].Enqueue(disk.ReadBytesPerSecond);
                _perDiskWriteHistory[diskIndex].Enqueue(disk.WriteBytesPerSecond);
                while (_perDiskReadHistory[diskIndex].Count > HistoryLimit) _perDiskReadHistory[diskIndex].Dequeue();
                while (_perDiskWriteHistory[diskIndex].Count > HistoryLimit) _perDiskWriteHistory[diskIndex].Dequeue();
            }
            diskIndex++;
        }

        // Clear extra gauges if fewer disks reported
        for (int i = diskIndex; i < _perDiskReadGauges.Count; i++)
        {
            _perDiskReadGauges[i].SetValue(null);
            _perDiskWriteGauges[i].SetValue(null);
        }

        var activeDiskCount = disks.Count(d => !string.Equals(d.InstanceName, "_Total", StringComparison.OrdinalIgnoreCase));
        PerDiskDetail.Text = activeDiskCount > 0
            ? $"Per-disk read/write throughput from Windows PhysicalDisk counters ({activeDiskCount} disks)"
            : "Per-disk I/O unavailable";
    }

    private void DrawPerDiskHistory()
    {
        if (PerDiskHistoryChart is null) return;
        var width = PerDiskHistoryChart.ActualWidth;
        var height = PerDiskHistoryChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;

        const double insetX = 60;
        const double insetY = 6;

        // Calculate peak for scaling
        double peak = 0;
        for (int i = 0; i < _perDiskReadHistory.Count; i++)
        {
            var readValues = _perDiskReadHistory[i].ToArray();
            var writeValues = _perDiskWriteHistory[i].ToArray();
            var readPeak = readValues.Where(v => v.HasValue).Select(v => v!.Value).DefaultIfEmpty(0).Max();
            var writePeak = writeValues.Where(v => v.HasValue).Select(v => v!.Value).DefaultIfEmpty(0).Max();
            peak = Math.Max(peak, Math.Max(readPeak, writePeak));
        }
        var scale = Math.Max(1024, peak);

        _perDiskHistoryGrid ??= new ChartGrid(PerDiskHistoryChart, insetX, insetY, 54, 12, 8,
            Color.FromArgb(36, 190, 220, 242), Color.FromArgb(170, 164, 184, 199));
        _perDiskHistoryGrid.Update(width, height, Enumerable.Range(0, 5)
            .Select(level => FormatRate((long)Math.Min(scale * (4 - level) / 4d, long.MaxValue))).ToArray());

        bool hasData = false;
        for (int i = 0; i < _perDiskReadHistory.Count; i++)
        {
            if (i < _perDiskReadHistorySeries.Count)
            {
                var readValues = _perDiskReadHistory[i].ToArray();
                var readPoints = MapRateSeries(readValues, width, height, scale, insetX, insetY);
                _perDiskReadHistorySeries[i].Update(readPoints, width - 8.1);
                if (readValues.Any(v => v.HasValue)) hasData = true;
            }
            if (i < _perDiskWriteHistorySeries.Count)
            {
                var writeValues = _perDiskWriteHistory[i].ToArray();
                var writePoints = MapRateSeries(writeValues, width, height, scale, insetX, insetY);
                _perDiskWriteHistorySeries[i].Update(writePoints, width - 8.1);
                if (writeValues.Any(v => v.HasValue)) hasData = true;
            }
        }
        if (PerDiskHistoryEmpty is not null)
        {
            PerDiskHistoryEmpty.Visibility = hasData
                ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;
        }
    }

    private void PerDiskHistoryHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawPerDiskHistory();

    private void DrawProcessCpuHistory()
    {
        if (ProcessCpuHistoryChart is null) return;
        var width = ProcessCpuHistoryChart.ActualWidth;
        var height = ProcessCpuHistoryChart.ActualHeight;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width <= 1 || height <= 1) return;

        const double insetX = 38;
        const double insetY = 7;

        if (!_selectedProcessPid.HasValue || !_processCpuHistory.TryGetValue(_selectedProcessPid.Value, out var queue))
        {
            if (ProcessCpuHistoryEmpty is not null)
                ProcessCpuHistoryEmpty.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
            if (ProcessCpuHistoryTitle is not null)
                ProcessCpuHistoryTitle.Text = "Select a process from the list to view CPU history";
            return;
        }

        var values = queue.ToArray();
        var points = MapSeries(values, width, height, insetX, insetY);

        _processCpuHistoryGrid ??= new ChartGrid(ProcessCpuHistoryChart, insetX, insetY, 31, 14, 9,
            Color.FromArgb(38, 190, 220, 242), Color.FromArgb(190, 164, 184, 199));
        _processCpuHistoryGrid.Update(width, height, ["100%", "75%", "50%", "25%", "0%"]);

        _processCpuHistorySeries ??= new ChartLineRenderer(ProcessCpuHistoryChart, Color.FromArgb(255, 255, 174, 92));
        _processCpuHistorySeries.Update(points, width - 8.1);

        bool hasData = values.Any(v => v.HasValue);
        if (ProcessCpuHistoryEmpty is not null)
        {
            ProcessCpuHistoryEmpty.Visibility = hasData
                ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;
        }
    }

    private void ProcessCpuHistoryHost_SizeChanged(object sender, Microsoft.UI.Xaml.SizeChangedEventArgs e) => DrawProcessCpuHistory();

    private static Point?[] MapRateSeries(double?[] values, double width, double height, double scale, double insetX, double insetY)
    {
        var points = new Point?[values.Length];
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] is not { } value) continue;
            var x = insetX + (width - insetX - 8) * index / Math.Max(1, values.Length - 1);
            var y = insetY + (height - insetY * 2) * (1 - Math.Clamp(value / scale, 0, 1));
            if (double.IsFinite(x) && double.IsFinite(y)) points[index] = new Point(x, y);
        }
        return points;
    }

    private sealed record PerformanceSample(DateTimeOffset CapturedAtUtc, double? Cpu, double? Memory, double? CommitPercent,
        ulong? CommittedBytes, ulong? CommitLimitBytes, long? Receive, long? Send, long? DiskRead, long? DiskWrite);
    private sealed record SystemVolumeReading(double? UsagePercent, string? DisplayValue, string Value, string Detail);
}

public sealed class PerformanceProcessRow : ObservableRow
{
    private int _processId;
    private string _name = "";
    private string _detail = "";
    private double _memoryShare;
    private Microsoft.UI.Xaml.Visibility _visibility = Microsoft.UI.Xaml.Visibility.Visible;

    public PerformanceProcessRow() { }
    public PerformanceProcessRow(int processId, string name, string detail, double memoryShare) =>
        (ProcessId, _name, _detail, _memoryShare) = (processId, name, detail, memoryShare);
    public int ProcessId { get => _processId; set => SetProperty(ref _processId, value); }
    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public string Detail { get => _detail; set => SetProperty(ref _detail, value); }
    public double MemoryShare { get => _memoryShare; set => SetProperty(ref _memoryShare, value); }
    public Microsoft.UI.Xaml.Visibility Visibility { get => _visibility; set => SetProperty(ref _visibility, value); }
}

/// <summary>Selects a file in File Explorer through the documented shell API (no process or command line is started by Downpour).</summary>
internal static class ShellSelect
{
    public static bool Reveal(string path)
    {
        var item = ILCreateFromPathW(path);
        if (item == IntPtr.Zero) return false;
        try { return SHOpenFolderAndSelectItems(item, 0, IntPtr.Zero, 0) == 0; }
        finally { ILFree(item); }
    }

    [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr ILCreateFromPathW(string path);

    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    private static extern void ILFree(IntPtr pidl);

    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    private static extern int SHOpenFolderAndSelectItems(IntPtr folder, uint count, IntPtr items, uint flags);
}
