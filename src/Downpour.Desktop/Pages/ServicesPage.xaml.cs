using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class ServicesPage : Page
{
    private readonly WindowsServiceInventoryClient _client = new();
    private readonly DispatcherQueueTimer _refreshTimer;
    private IReadOnlyList<WindowsServiceRow> _allServices = [];
    private bool _requestInFlight;

    public ObservableCollection<WindowsServiceRow> Services { get; } = [];

    public ServicesPage()
    {
        InitializeComponent();
        _refreshTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _refreshTimer.Interval = TimeSpan.FromSeconds(1);
        _refreshTimer.IsRepeating = true;
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
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

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

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
                StatusHeadline.Text = "Downpour is running · Windows service sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted service data is shown.";
                ServiceCount.Text = "SERVICE OFFLINE";
                _allServices = [];
                ApplyFilter();
                return;
            }

            App.MarkSensorServiceConnected();
            _allServices = snapshot.Services.Select(ToRow)
                .OrderBy(row => row.ServiceName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            StatusHeadline.Text = snapshot.CollectionStatus switch
            {
                "Available" => "Windows Service Control Manager inventory connected",
                "Partial" => "Windows service inventory is partial",
                "Access denied" => "Access denied to the Windows Service Control Manager",
                _ => "Windows service inventory is unavailable"
            };
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            StatusDetail.Text = snapshot.Warnings.Count == 0
                ? $"Captured {captured:MMM d · HH:mm:ss}. Service state and startup type are read locally; no service changes are performed."
                : $"Captured {captured:MMM d · HH:mm:ss}. {string.Join(" ", snapshot.Warnings)}";
            ApplyFilter(snapshot.ServiceCount, snapshot.CollectionStatus);
        }
        finally
        {
            _requestInFlight = false;
        }
    }

    private static WindowsServiceRow ToRow(WindowsServiceInventoryEntry service)
    {
        static SolidColorBrush StateColor(string value) => new(value switch
        {
            "Running" => Color.FromArgb(255, 116, 220, 170),
            "Stopped" => Color.FromArgb(255, 171, 186, 201),
            "Start pending" or "Stop pending" or "Continue pending" or "Pause pending" => Color.FromArgb(255, 105, 211, 235),
            "Paused" => Color.FromArgb(255, 255, 198, 112),
            "Access denied" => Color.FromArgb(255, 255, 177, 107),
            _ => Color.FromArgb(255, 193, 199, 213)
        });

        var riskBrush = new SolidColorBrush(service.Risk switch
        {
            "Critical" or "High" => Color.FromArgb(255, 255, 120, 110),
            "Medium" => Color.FromArgb(255, 255, 170, 90),
            "Low" => Color.FromArgb(255, 255, 214, 102),
            _ => Color.FromArgb(255, 116, 220, 170)
        });
        var indicators = service.RiskIndicators is { Count: > 0 } list ? string.Join(" · ", list) : "";
        var detail = string.Join(" — ", new[] { service.ImagePath, indicators }.Where(part => part.Length > 0));
        return new WindowsServiceRow(service.ServiceName, service.DisplayName, service.State, service.StartupType,
            StateColor(service.State), StateColor(service.StartupType), service.Risk, riskBrush, detail);
    }

    private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => ApplyFilter();
    private void ShowClean_Changed(object sender, RoutedEventArgs e) => ApplyFilter();

    private void ApplyFilter(int? reportedCount = null, string? collectionStatus = null)
    {
        if (ServiceList is null) return;
        var query = SearchBox.Text?.Trim() ?? "";
        var showClean = ShowClean?.IsChecked == true;
        var filtered = _allServices.Where(row => (showClean || row.Risk != ServiceRiskAnalyzer.Clean) && (query.Length == 0 ||
                row.ServiceName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.RiskDetail.Contains(query, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(row => Array.IndexOf(["Critical", "High", "Medium", "Low", "Clean"], row.Risk))
            .ThenBy(row => row.ServiceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (RiskSummary is not null)
            RiskSummary.Text = string.Join("  ·  ", new[] { "Critical", "High", "Medium", "Low", "Clean" }
                .Select(level => $"{level.ToUpperInvariant()}: {_allServices.Count(row => row.Risk == level)}"));
        CollectionReconciler.Apply(Services, filtered, row => row.Key,
            (current, incoming) => current.UpdateFrom(incoming));

        EmptyState.Visibility = Services.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (collectionStatus is not null)
        {
            var count = reportedCount ?? _allServices.Count;
            ServiceCount.Text = collectionStatus == "Partial"
                ? $"AT LEAST {count:N0} · {Services.Count:N0} SHOWN"
                : $"{Services.Count:N0} SHOWN OF {count:N0}";
        }
    }
}

public sealed class WindowsServiceRow : ObservableRow
{
    private string _serviceName;
    private string _displayName;
    private string _state;
    private string _startupType;
    private SolidColorBrush _stateBrush;
    private SolidColorBrush _startupBrush;
    private string _risk;
    private SolidColorBrush _riskBrush;
    private string _riskDetail;

    public WindowsServiceRow(string serviceName, string displayName, string state, string startupType,
        SolidColorBrush stateBrush, SolidColorBrush startupBrush, string risk, SolidColorBrush riskBrush, string riskDetail)
    {
        _risk = risk;
        _riskBrush = riskBrush;
        _riskDetail = riskDetail;
        _serviceName = serviceName;
        _displayName = displayName;
        _state = state;
        _startupType = startupType;
        _stateBrush = stateBrush;
        _startupBrush = startupBrush;
    }

    public string Key => ServiceName.ToUpperInvariant();
    public string ServiceName { get => _serviceName; private set => SetProperty(ref _serviceName, value); }
    public string DisplayName { get => _displayName; private set => SetProperty(ref _displayName, value); }
    public string State { get => _state; private set => SetProperty(ref _state, value); }
    public string StartupType { get => _startupType; private set => SetProperty(ref _startupType, value); }
    public SolidColorBrush StateBrush { get => _stateBrush; private set => SetBrush(ref _stateBrush, value, nameof(StateBrush)); }
    public SolidColorBrush StartupBrush { get => _startupBrush; private set => SetBrush(ref _startupBrush, value, nameof(StartupBrush)); }
    public string Risk { get => _risk; private set => SetProperty(ref _risk, value); }
    public SolidColorBrush RiskBrush { get => _riskBrush; private set => SetBrush(ref _riskBrush, value, nameof(RiskBrush)); }
    public string RiskDetail { get => _riskDetail; private set => SetProperty(ref _riskDetail, value); }

    public void UpdateFrom(WindowsServiceRow incoming)
    {
        ServiceName = incoming.ServiceName;
        DisplayName = incoming.DisplayName;
        State = incoming.State;
        StartupType = incoming.StartupType;
        StateBrush = incoming.StateBrush;
        StartupBrush = incoming.StartupBrush;
        Risk = incoming.Risk;
        RiskBrush = incoming.RiskBrush;
        RiskDetail = incoming.RiskDetail;
    }

    private void SetBrush(ref SolidColorBrush current, SolidColorBrush incoming, string propertyName)
    {
        if (current.Color == incoming.Color) return;
        current = incoming;
        RaisePropertyChanged(propertyName);
    }
}
