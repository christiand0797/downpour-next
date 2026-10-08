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
    private readonly ThreatDatabaseClient _threats = new();
    private IReadOnlyList<ThreatMatch> _matches = [];
    private DateTimeOffset _matchesFetched = DateTimeOffset.MinValue;
    private readonly DispatcherQueueTimer _refreshTimer;
    private IReadOnlyList<DriverRow> _allDrivers = [];
    private bool _requestInFlight;

    public ObservableCollection<DriverRow> Drivers { get; } = [];

    private readonly BreakdownChart _signatureChart = new() { Title = "Driver signatures", Subtitle = "Embedded Authenticode or Windows catalog, verified on this PC" };
    private readonly BreakdownChart _locationChart = new() { Title = "Driver locations", Subtitle = "Folders standard users can write to are a BYOVD risk" };
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
        _signatureChart.SetData(
        [
            ("Microsoft", snapshot.Drivers.Count(d => d.Signed == true && d.MicrosoftSigned)),
            ("Vendor signed", snapshot.Drivers.Count(d => d.Signed == true && !d.MicrosoftSigned)),
            ("Not validly signed", snapshot.Drivers.Count(d => d.Signed == false)),
            ("Not checked", snapshot.Drivers.Count(d => d.Signed is null)),
        ], new Dictionary<string, Windows.UI.Color> { ["Not validly signed"] = HudPalette.Critical });
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
        Charts.Row(ChartRow, _signatureChart, _locationChart, _folderChart, _countChart);
        EntityDetails.Attach(DriverList, item => item is DriverRow d ? new DetailEntity(d.Name, $"Loaded kernel driver · {d.Verdict}",
        [
            new("Verdict", $"{d.Severity} · {d.Verdict}"), new("Why", d.Explanation), new("Signature", d.Signature),
            new("Name", d.Name), new("Image path", d.ImagePath), new("Location", d.LocationStatus),
        ], FilePath: d.ImagePath, Kind: "driver") : null);
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

            await RefreshMatchesAsync();
            var matches = _matches;
            _allDrivers = snapshot.Drivers.Select(d => ToRow(d, matches))
                .OrderBy(row => SeverityRank(row.Severity)).ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            UpdateCharts(snapshot);
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var flagged = _allDrivers.Count(r => r.Severity is "CRITICAL" or "HIGH" or "MEDIUM");
            InventoryStatus.Text = $"{snapshot.DriverCount:N0} loaded kernel drivers · {snapshot.Drivers.Count(d => d.Signed == true):N0} validly signed · " +
                                   (flagged == 0 ? "none flagged" : $"{flagged:N0} need attention") + $" · captured {captured:HH:mm:ss}" +
                                   (snapshot.Warnings.Count > 0 ? $" · {string.Join(" ", snapshot.Warnings)}" : "");
            DriverCount.Text = $"{_allDrivers.Count:N0} SHOWN";
            ApplyFilter();
        }
        finally
        {
            _requestInFlight = false;
        }
    }

    /// <summary>LOLDrivers hash matches from the threat database sweep; refreshed at most every 15 seconds.</summary>
    private async Task RefreshMatchesAsync()
    {
        if (DateTimeOffset.UtcNow - _matchesFetched < TimeSpan.FromSeconds(15)) return;
        _matchesFetched = DateTimeOffset.UtcNow;
        var response = await _threats.GetSnapshotAsync();
        if (response?.Snapshot is { } threat) _matches = threat.Matches.Where(m => m.Where == ThreatMatchPlaces.Driver).ToArray();
    }

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "INFO" => 3, _ => 4,
    };

    private static DriverRow ToRow(DriverInventoryEntry driver, IReadOnlyList<ThreatMatch> matches)
    {
        var location = driver.IsInUserWritableLocation ? "User-writable folder"
            : driver.IsUnderSystemDrivers ? "System drivers folder" : "Other system folder";
        var signature = driver.Signed switch
        {
            true when driver.MicrosoftSigned => "Microsoft",
            true => PersistenceAnalyzer.SignerDisplay(driver.Signer),
            false => "NOT validly signed",
            _ => "Not checked",
        };
        var verdict = DriverAssessment.Assess(driver, matches);
        var color = verdict.Severity switch
        {
            "CRITICAL" => Color.FromArgb(255, 255, 94, 94),
            "HIGH" => Color.FromArgb(255, 255, 140, 70),
            "MEDIUM" => Color.FromArgb(255, 255, 181, 86),
            "OK" => Color.FromArgb(255, 142, 202, 171),
            _ => Color.FromArgb(255, 201, 192, 157),
        };
        return new DriverRow(driver.Name, string.IsNullOrWhiteSpace(driver.ImagePath) ? "Path unavailable" : driver.ImagePath,
            location, signature, verdict.Severity, verdict.Title, verdict.Explanation, new SolidColorBrush(color));
    }

    private void DriverSearch_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => ApplyFilter();

    private void ApplyFilter()
    {
        var query = DriverSearch?.Text?.Trim() ?? "";
        var filtered = _allDrivers.Where(row => query.Length == 0 ||
                row.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.ImagePath.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Signature.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Verdict.Contains(query, StringComparison.OrdinalIgnoreCase))
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
    private string _signature = "";
    private string _severity = "";
    private string _verdict = "";
    private string _explanation = "";
    private SolidColorBrush _statusBrush = new(Color.FromArgb(255, 201, 192, 157));

    public DriverRow() { }

    public DriverRow(string name, string imagePath, string locationStatus, string signature, string severity, string verdict, string explanation,
        SolidColorBrush statusBrush) =>
        (_name, _imagePath, _locationStatus, _signature, _severity, _verdict, _explanation, _statusBrush) =
        (name, imagePath, locationStatus, signature, severity, verdict, explanation, statusBrush);

    public string Key => $"{Name.ToUpperInvariant()}\0{ImagePath.ToUpperInvariant()}";
    public string Name { get => _name; private set => SetProperty(ref _name, value); }
    public string ImagePath { get => _imagePath; private set => SetProperty(ref _imagePath, value); }
    public string LocationStatus { get => _locationStatus; private set => SetProperty(ref _locationStatus, value); }
    public string Signature { get => _signature; private set => SetProperty(ref _signature, value); }
    public string Severity { get => _severity; private set => SetProperty(ref _severity, value); }
    public string Verdict { get => _verdict; private set => SetProperty(ref _verdict, value); }
    public string Explanation { get => _explanation; private set => SetProperty(ref _explanation, value); }
    public SolidColorBrush StatusBrush { get => _statusBrush; private set => SetBrush(ref _statusBrush, value); }

    public void UpdateFrom(DriverRow incoming)
    {
        Name = incoming.Name;
        ImagePath = incoming.ImagePath;
        LocationStatus = incoming.LocationStatus;
        Signature = incoming.Signature;
        Severity = incoming.Severity;
        Verdict = incoming.Verdict;
        Explanation = incoming.Explanation;
        StatusBrush = incoming.StatusBrush;
    }

    private void SetBrush(ref SolidColorBrush current, SolidColorBrush incoming)
    {
        if (current.Color == incoming.Color) return;
        current = incoming;
        RaisePropertyChanged(nameof(StatusBrush));
    }
}
