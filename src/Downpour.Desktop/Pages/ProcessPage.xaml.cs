using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class ProcessPage : Page
{
    private readonly SystemSnapshotClient _client = new();
    private readonly DispatcherQueueTimer _timer;
    private IReadOnlyList<ProcessRow> _allProcesses = [];
    private int _totalProcessCount;
    private bool _hasSnapshot;
    private bool _refreshing;

    public ObservableCollection<ProcessRow> Processes { get; } = [];

    private readonly TopBarsChart _cpuChart = new() { Title = "Top CPU", Subtitle = "Share of all processors, summed per program" };
    private readonly TopBarsChart _memoryChart = new() { Title = "Top memory", Subtitle = "Working set, summed per program" };
    private readonly TrendChart _countChart = new() { Title = "Processes running", Subtitle = "Sampled every second while this page is open" };

    public ProcessPage()
    {
        InitializeComponent();
        _memoryChart.Limit = _cpuChart.Limit = 6;
        Charts.Row(ChartRow, _cpuChart, _memoryChart, _countChart);
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.IsRepeating = true;
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (!_timer.IsRunning) _timer.Start();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _timer.Stop();
        base.OnNavigatedFrom(e);
    }

    private async Task RefreshAsync()
    {
        if (_refreshing) return;
        _refreshing = true;
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
                SnapshotStatus.Text = $"Downpour is running, but the sensor service is offline. {App.SensorServiceStatusHint}";
                _totalProcessCount = 0;
                _hasSnapshot = false;
                _allProcesses = [];
                ApplyFilter();
                return;
            }

            _allProcesses = snapshot.TopProcesses.Select(process => new ProcessRow(
                process.ProcessId,
                process.Name,
                process.WorkingSetBytes,
                process.ThreadCount,
                process.CpuPercent)).ToArray();
            _totalProcessCount = snapshot.ProcessCount;
            _hasSnapshot = true;
            var byProgram = snapshot.TopProcesses.GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            _cpuChart.SetData(byProgram.Select(g => (g.Key, g.Sum(p => p.CpuPercent ?? 0))), "%",
                colorFor: value => value >= 50 ? HudPalette.Serious : null);
            _memoryChart.SetData(byProgram.Select(g => (g.Key, g.Sum(p => p.WorkingSetBytes) / 1048576.0)), " MB", HudPalette.Categorical[1]);
            _countChart.Push(snapshot.ProcessCount, snapshot.CapturedAtUtc.ToLocalTime());
            SnapshotStatus.Text = $"Observe-only · {snapshot.ProcessCount:N0} processes on this device · refreshed {snapshot.CapturedAtUtc.ToLocalTime():T}";
            ApplyFilter();
        }
        finally
        {
            _refreshing = false;
        }
    }

    private void ApplyFilter()
    {
        if (!_hasSnapshot)
        {
            Processes.Clear();
            if (ProcessCount is not null) ProcessCount.Text = "";
            return;
        }
        var query = ProcessSearch?.Text?.Trim() ?? "";
        var visible = string.IsNullOrEmpty(query)
            ? _allProcesses
            : _allProcesses.Where(process => process.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                process.ProcessId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        CollectionReconciler.Apply(Processes, visible.ToArray(), process => process.ProcessId, (current, incoming) =>
        {
            current.Name = incoming.Name;
            current.WorkingSetBytes = incoming.WorkingSetBytes;
            current.ThreadCount = incoming.ThreadCount;
            current.CpuPercent = incoming.CpuPercent;
        });
        if (ProcessCount is not null)
        {
            ProcessCount.Text = string.IsNullOrWhiteSpace(query)
                ? $"Showing {_allProcesses.Count:N0} of {_totalProcessCount:N0} processes · sorted by memory"
                : $"{visible.Count:N0} matches in top {_allProcesses.Count:N0} of {_totalProcessCount:N0}";
        }
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private void ProcessSearch_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => ApplyFilter();
}

public sealed class ProcessRow : ObservableRow
{
    private int _processId;
    private string _name = "";
    private long _workingSetBytes;
    private int _threadCount;
    private double? _cpuPercent;

    public ProcessRow() { }
    public ProcessRow(int processId, string name, long workingSetBytes, int threadCount, double? cpuPercent = null) =>
        (_processId, _name, _workingSetBytes, _threadCount, _cpuPercent) = (processId, name, workingSetBytes, threadCount, cpuPercent);

    public int ProcessId { get => _processId; set => SetProperty(ref _processId, value); }
    public string Name { get => _name; set => SetProperty(ref _name, value); }
    public long WorkingSetBytes
    {
        get => _workingSetBytes;
        set { if (SetProperty(ref _workingSetBytes, value)) RaisePropertyChanged(nameof(MemoryDisplay)); }
    }
    public int ThreadCount { get => _threadCount; set => SetProperty(ref _threadCount, value); }
    public double? CpuPercent
    {
        get => _cpuPercent;
        set { if (SetProperty(ref _cpuPercent, value)) RaisePropertyChanged(nameof(CpuDisplay)); }
    }
    public string CpuDisplay => CpuPercent is { } value ? $"{value:0.0}%" : "—";
    public string MemoryDisplay => $"{WorkingSetBytes / 1024d / 1024d:0.0} MB";
}
