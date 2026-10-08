using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class DriverPage : Page
{
    private readonly DriverInventoryClient _client = new();
    private readonly DispatcherQueueTimer _refreshTimer;
    private IReadOnlyList<DriverRow> _allDrivers = [];
    private bool _requestInFlight;

    public ObservableCollection<DriverRow> Drivers { get; } = [];

    private readonly BreakdownChart _locationChart = new() { Title = "Where drivers load from", Subtitle = "Drivers in folders standard users can write to are a BYOVD risk" };
    private readonly TopBarsChart _folderChart = new() { Title = "Drivers by folder", Subtitle = "Loaded kernel drivers per folder" };
    private readonly TrendChart _countChart = new() { Title = "Loaded kernel drivers", Subtitle = "Sampled while this page is open" };

    private void FindUpdates_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => App.NavigateToRoute("devices");

    private void DeviceManager_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("devmgmt.msc") { UseShellExecute = true })?.Dispose(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    private void UpdateCharts(DriverInventorySnapshot snapshot)
    {
        _locationChart.SetData(
        [
            ("System drivers folder", snapshot.Drivers.Count(d => d.IsUnderSystemDrivers)),
            ("Other system folders", snapshot.Drivers.Count(d => !d.IsUnderSystemDrivers && !d.IsInUserWritableLocation)),
            ("User-writable folder", snapshot.Drivers.Count(d => d.IsInUserWritableLocation)),
        ], new Dictionary<string, Windows.UI.Color> { ["User-writable folder"] = HudPalette.Critical });
        _folderChart.SetData(snapshot.Drivers
            .GroupBy(d => FolderLabel(d.ImagePath), StringComparer.OrdinalIgnoreCase)
            .Select(g => (g.Key, (double)g.Count())));
        _countChart.Push(snapshot.DriverCount, snapshot.CapturedAtUtc.ToLocalTime());
    }

    private static string FolderLabel(string path)
    {
        var folder = Path.GetDirectoryName(path.Replace(@"\??\", "").Replace(@"\SystemRoot\", @"C:\Windows\")) ?? "";
        var parts = folder.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 0 ? "(no path)" : string.Join("\\", parts.TakeLast(2));
    }

    public DriverPage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _locationChart, _folderChart, _countChart);
        EntityDetails.Attach(DriverList, item => item is DriverRow d ? new DetailEntity(d.Name, "Loaded kernel driver",
            [new("Name", d.Name), new("Image path", d.ImagePath), new("Location", d.LocationStatus)], FilePath: d.ImagePath, Kind: "driver") : null);
        _refreshTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _refreshTimer.Interval = TimeSpan.FromSeconds(1);
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
                InventoryStatus.Text = $"Downpour is running, but its driver telemetry service is offline. {App.SensorServiceStatusHint} No local data is being substituted.";
                DriverCount.Text = "SERVICE OFFLINE";
                _allDrivers = [];
                ApplyFilter();
                return;
            }

            _allDrivers = snapshot.Drivers.Select(ToRow).OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            UpdateCharts(snapshot);
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            InventoryStatus.Text = $"{snapshot.DriverCount:N0} loaded kernel drivers · captured {captured:HH:mm:ss}" +
                                   (snapshot.Warnings.Count > 0 ? $" · {string.Join(" ", snapshot.Warnings)}" : "");
            DriverCount.Text = $"{_allDrivers.Count:N0} SHOWN";
            ApplyFilter();
        }
        finally
        {
            _requestInFlight = false;
        }
    }

    private static DriverRow ToRow(DriverInventoryEntry driver)
    {
        var (status, color) = driver.IsInUserWritableLocation
            ? ("Review · user-writable path", Color.FromArgb(255, 255, 181, 86))
            : driver.IsUnderSystemDrivers
                ? ("Standard driver path · signature unknown", Color.FromArgb(255, 142, 202, 171))
                : ("Path not classified · signature unknown", Color.FromArgb(255, 201, 192, 157));

        return new DriverRow(driver.Name, string.IsNullOrWhiteSpace(driver.ImagePath) ? "Path unavailable" : driver.ImagePath,
            status, new SolidColorBrush(color));
    }

    private void DriverSearch_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => ApplyFilter();

    private void ApplyFilter()
    {
        var query = DriverSearch?.Text?.Trim() ?? "";
        var filtered = _allDrivers.Where(row => query.Length == 0 ||
                row.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.ImagePath.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        CollectionReconciler.Apply(Drivers, filtered, row => row.Key,
            (current, incoming) => current.UpdateFrom(incoming));
    }
}

public sealed class DriverRow : ObservableRow
{
    private string _name = "";
    private string _imagePath = "";
    private string _locationStatus = "";
    private SolidColorBrush _statusBrush = new(Color.FromArgb(255, 201, 192, 157));

    public DriverRow() { }

    public DriverRow(string name, string imagePath, string locationStatus, SolidColorBrush statusBrush) =>
        (_name, _imagePath, _locationStatus, _statusBrush) = (name, imagePath, locationStatus, statusBrush);

    public string Key => $"{Name.ToUpperInvariant()}\0{ImagePath.ToUpperInvariant()}";
    public string Name { get => _name; private set => SetProperty(ref _name, value); }
    public string ImagePath { get => _imagePath; private set => SetProperty(ref _imagePath, value); }
    public string LocationStatus { get => _locationStatus; private set => SetProperty(ref _locationStatus, value); }
    public SolidColorBrush StatusBrush { get => _statusBrush; private set => SetBrush(ref _statusBrush, value); }

    public void UpdateFrom(DriverRow incoming)
    {
        Name = incoming.Name;
        ImagePath = incoming.ImagePath;
        LocationStatus = incoming.LocationStatus;
        StatusBrush = incoming.StatusBrush;
    }

    private void SetBrush(ref SolidColorBrush current, SolidColorBrush incoming)
    {
        if (current.Color == incoming.Color) return;
        current = incoming;
        RaisePropertyChanged(nameof(StatusBrush));
    }
}
