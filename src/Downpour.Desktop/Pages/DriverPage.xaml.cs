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

    public DriverPage()
    {
        InitializeComponent();
        _refreshTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _refreshTimer.Interval = TimeSpan.FromSeconds(30);
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
        Drivers.Clear();
        foreach (var row in _allDrivers.Where(row => query.Length == 0 ||
                     row.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                     row.ImagePath.Contains(query, StringComparison.OrdinalIgnoreCase)))
        {
            Drivers.Add(row);
        }
    }
}

public sealed class DriverRow
{
    public DriverRow() { }

    public DriverRow(string name, string imagePath, string locationStatus, SolidColorBrush statusBrush) =>
        (Name, ImagePath, LocationStatus, StatusBrush) = (name, imagePath, locationStatus, statusBrush);

    public string Name { get; set; } = "";
    public string ImagePath { get; set; } = "";
    public string LocationStatus { get; set; } = "";
    public SolidColorBrush StatusBrush { get; set; } = new(Color.FromArgb(255, 201, 192, 157));
}
