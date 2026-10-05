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

    public ProcessPage()
    {
        InitializeComponent();
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(5);
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
        Processes.Clear();
        foreach (var process in visible) Processes.Add(process);
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

public sealed class ProcessRow
{
    public ProcessRow() { }
    public ProcessRow(int processId, string name, long workingSetBytes, int threadCount, double? cpuPercent = null) =>
        (ProcessId, Name, WorkingSetBytes, ThreadCount, CpuPercent) = (processId, name, workingSetBytes, threadCount, cpuPercent);

    public int ProcessId { get; set; }
    public string Name { get; set; } = "";
    public long WorkingSetBytes { get; set; }
    public int ThreadCount { get; set; }
    public double? CpuPercent { get; set; }
    public string CpuDisplay => CpuPercent is { } value ? $"{value:0.0}%" : "—";
    public string MemoryDisplay => $"{WorkingSetBytes / 1024d / 1024d:0.0} MB";
}
