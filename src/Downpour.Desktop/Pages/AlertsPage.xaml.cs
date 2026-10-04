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

public sealed partial class AlertsPage : Page
{
    private readonly SecurityAlertClient _client = new();
    private readonly DispatcherQueueTimer _refreshTimer;
    private IReadOnlyList<SecurityAlert> _allAlerts = [];
    private bool _requestInFlight;
    private bool _stateChangeInFlight;

    public ObservableCollection<SecurityAlertRow> Alerts { get; } = [];

    public AlertsPage()
    {
        InitializeComponent();
        _refreshTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _refreshTimer.Interval = TimeSpan.FromSeconds(15);
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
                StatusHeadline.Text = "Downpour is running · local alert sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted alert data is shown.";
                _allAlerts = [];
                AlertCount.Text = "ALERT STORE OFFLINE";
                ApplyFilters();
                return;
            }

            App.MarkSensorServiceConnected();
            _allAlerts = snapshot.Alerts;
            var openCount = snapshot.Alerts.Count(alert => alert.State == "Open");
            StatusHeadline.Text = snapshot.Warnings.Count == 0
                ? "Local security alert monitor connected"
                : "Event collection or alert storage is partially unavailable";
            StatusDetail.Text = snapshot.Warnings.Count == 0
                ? $"Captured {snapshot.CapturedAtUtc.ToLocalTime():MMM d · HH:mm:ss}. {openCount:N0} open in the latest {snapshot.Alerts.Count:N0} of {snapshot.TotalCount:N0} retained alerts; retention is 30 days / 10,000 alerts."
                : string.Join("  •  ", snapshot.Warnings);
            ApplyFilters(snapshot.TotalCount);
        }
        finally { _requestInFlight = false; }
    }

    private async void Acknowledge_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "Acknowledged");
    private async void Suppress_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "Suppressed");
    private async void Reopen_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "Open");

    private async Task ChangeStateFromButtonAsync(object sender, string nextState)
    {
        if (_stateChangeInFlight || sender is not Button { Tag: string alertId }) return;
        var alert = _allAlerts.FirstOrDefault(candidate => candidate.AlertId == alertId);
        if (alert is null) return;

        _stateChangeInFlight = true;
        try
        {
            StatusHeadline.Text = $"Saving local triage state: {nextState}";
            var request = new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, alert.State, nextState);
            var response = await _client.ChangeStateAsync(request);
            if (response is null)
            {
                StatusHeadline.Text = "Local triage pipe unavailable";
                StatusDetail.Text = "No status change was confirmed. Refresh the alert list before retrying.";
                return;
            }
            if (!response.Accepted)
            {
                StatusHeadline.Text = "Alert state changed elsewhere or request was rejected";
                StatusDetail.Text = $"Result: {response.ResultCode}. Refresh the list and retry against its current state.";
            }
            else
            {
                StatusHeadline.Text = response.ResultCode == "updated" ? "Local triage state saved" : "Alert state is already current";
                StatusDetail.Text = "Only local alert review state changed. No operating-system setting or process was touched.";
            }
            await RefreshAsync();
        }
        finally { _stateChangeInFlight = false; }
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilters();
    private void StateFilter_SelectionChanged(object sender, SelectionChangedEventArgs e) => ApplyFilters();

    private void ApplyFilters(int? total = null)
    {
        if (AlertList is null) return;
        var search = SearchBox.Text.Trim();
        var state = (StateFilter.SelectedItem as ComboBoxItem)?.Content?.ToString();
        var rows = _allAlerts.Where(alert => string.IsNullOrWhiteSpace(state) || state == "All states" || alert.State == state)
            .Where(alert => string.IsNullOrWhiteSpace(search) || alert.Title.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                alert.LogName.Contains(search, StringComparison.OrdinalIgnoreCase) || alert.Provider.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                alert.EventId.ToString().Contains(search, StringComparison.OrdinalIgnoreCase) || alert.Technique.Contains(search, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(alert => alert.FirstSeenUtc)
            .ToArray();

        Alerts.Clear();
        foreach (var alert in rows) Alerts.Add(ToRow(alert));
        EmptyState.Visibility = Alerts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (total is { } count) AlertCount.Text = $"{Alerts.Count:N0} shown / {count:N0} retained";
    }

    private static SecurityAlertRow ToRow(SecurityAlert alert)
    {
        var severityColor = alert.Severity switch
        {
            "CRITICAL" => Color.FromArgb(255, 255, 86, 121),
            "HIGH" => Color.FromArgb(255, 255, 167, 82),
            "MEDIUM" => Color.FromArgb(255, 255, 218, 119),
            _ => Color.FromArgb(255, 86, 210, 235)
        };
        var stateColor = alert.State switch
        {
            "Acknowledged" => Color.FromArgb(255, 112, 211, 163),
            "Suppressed" => Color.FromArgb(255, 169, 180, 195),
            _ => Color.FromArgb(255, 255, 177, 107)
        };
        return new SecurityAlertRow(alert.AlertId, alert.FirstSeenUtc.ToLocalTime().ToString("MMM d HH:mm:ss"), alert.Title,
            $"{alert.LogName} · {alert.Provider} · event {alert.EventId} / record {alert.RecordId?.ToString() ?? "unavailable"} · {alert.Technique}",
            alert.Severity, new SolidColorBrush(severityColor), alert.State, new SolidColorBrush(stateColor),
            alert.Occurrences == 1 ? "1 occurrence" : $"{alert.Occurrences:N0} occurrences",
            alert.State == "Open", alert.State == "Open", alert.State != "Open");
    }
}

public sealed class SecurityAlertRow(
    string alertId, string firstSeen, string title, string evidence, string severity, SolidColorBrush severityBrush,
    string state, SolidColorBrush stateBrush, string occurrences, bool canAcknowledge, bool canSuppress, bool canReopen)
{
    public string AlertId { get; } = alertId;
    public string FirstSeen { get; } = firstSeen;
    public string Title { get; } = title;
    public string Evidence { get; } = evidence;
    public string Severity { get; } = severity;
    public SolidColorBrush SeverityBrush { get; } = severityBrush;
    public string State { get; } = state;
    public SolidColorBrush StateBrush { get; } = stateBrush;
    public string Occurrences { get; } = occurrences;
    public bool CanAcknowledge { get; } = canAcknowledge;
    public bool CanSuppress { get; } = canSuppress;
    public bool CanReopen { get; } = canReopen;
}
