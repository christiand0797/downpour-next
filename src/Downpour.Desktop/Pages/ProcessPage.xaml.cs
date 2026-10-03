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
                SnapshotStatus.Text = "Service disconnected. Start Downpour.Service to load a process snapshot.";
                ProcessCount.Text = "";
                _allProcesses = [];
                ApplyFilter();
                return;
            }

            _allProcesses = snapshot.TopProcesses.Select(process => new ProcessRow(
                process.ProcessId,
                process.Name,
                process.WorkingSetBytes,
                process.ThreadCount)).ToArray();
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
        var query = ProcessSearch?.Text?.Trim() ?? "";
        var visible = string.IsNullOrEmpty(query)
            ? _allProcesses
            : _allProcesses.Where(process => process.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                process.ProcessId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        Processes.Clear();
        foreach (var process in visible) Processes.Add(process);
        if (ProcessCount is not null) ProcessCount.Text = $"{visible.Count:N0} shown · top {visible.Count} by memory";
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private void ProcessSearch_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => ApplyFilter();
}

public sealed class ProcessRow
{
    public ProcessRow() { }
    public ProcessRow(int processId, string name, long workingSetBytes, int threadCount) =>
        (ProcessId, Name, WorkingSetBytes, ThreadCount) = (processId, name, workingSetBytes, threadCount);

    public int ProcessId { get; set; }
    public string Name { get; set; } = "";
    public long WorkingSetBytes { get; set; }
    public int ThreadCount { get; set; }
    public string MemoryDisplay => $"{WorkingSetBytes / 1024d / 1024d:0.0} MB";
}
