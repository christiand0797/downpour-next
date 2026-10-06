using System.Collections.ObjectModel;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class InvestigationTimelinePage : Page
{
    private readonly SecurityAlertClient _client = new();
    private IReadOnlyList<SecurityAlert> _allAlerts = [];
    private string? _findingId;
    private CorrelatedAlertFinding? _currentFinding;
    private SecurityAlertSnapshot? _currentSnapshot;
    private bool _requestInFlight;

    public ObservableCollection<TimelineEventRow> TimelineEvents { get; } = [];

    public InvestigationTimelinePage() => InitializeComponent();

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is string findingId)
        {
            _findingId = findingId;
            await RefreshAsync();
        }
        else
        {
            FindingTitle.Text = "No finding ID provided";
            StatusHeadline.Text = "Invalid navigation";
            StatusDetail.Text = "Navigate from the Alerts page with a correlation finding ID.";
        }
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_requestInFlight || _findingId is null) return;
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
                StatusHeadline.Text = "Local alert sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} Cannot load investigation timeline without alert data.";
                return;
            }

            _currentSnapshot = snapshot;
            _allAlerts = snapshot.Alerts;

            // Find the correlation finding
            var correlated = AlertCorrelationEngine.Correlate(snapshot);
            _currentFinding = correlated.FirstOrDefault(f => f.CorrelationId == _findingId);

            if (_currentFinding is null)
            {
                FindingTitle.Text = "Finding not found";
                FindingDetail.Text = $"No correlation finding with ID {_findingId} found in the current snapshot.";
                StatusHeadline.Text = "Finding not in current snapshot";
                return;
            }

            FindingTitle.Text = _currentFinding.Title;
            FindingDetail.Text = $"Rule: {_currentFinding.RuleId} · Severity: {_currentFinding.Severity} · Technique: {_currentFinding.Technique}\n{_currentFinding.Limitation}\nFirst event: {_currentFinding.FirstEventUtc:O} · Last event: {_currentFinding.LastEventUtc:O}\nEvidence Alert IDs: {string.Join(", ", _currentFinding.EvidenceAlertIds)}";

            // Build timeline events from all alerts that match the evidence IDs or are in the same time window
            var timeWindowStart = _currentFinding.FirstEventUtc.Subtract(TimeSpan.FromMinutes(30));
            var timeWindowEnd = _currentFinding.LastEventUtc.Add(TimeSpan.FromMinutes(30));

            var timelineAlerts = _allAlerts
                .Where(a => _currentFinding.EvidenceAlertIds.Contains(a.AlertId) ||
                    (a.EventTimeUtc >= timeWindowStart && a.EventTimeUtc <= timeWindowEnd))
                .OrderBy(a => a.EventTimeUtc)
                .ToArray();

            TimelineEvents.Clear();
            foreach (var alert in timelineAlerts)
            {
                var isEvidence = _currentFinding.EvidenceAlertIds.Contains(alert.AlertId);
                var severityColor = alert.Severity switch
                {
                    "CRITICAL" => Color.FromArgb(255, 255, 86, 121),
                    "HIGH" => Color.FromArgb(255, 255, 167, 82),
                    "MEDIUM" => Color.FromArgb(255, 255, 218, 119),
                    _ => Color.FromArgb(255, 86, 210, 235)
                };
                TimelineEvents.Add(new TimelineEventRow(
                    alert.AlertId,
                    alert.EventTimeUtc.ToLocalTime().ToString("MMM d HH:mm:ss"),
                    alert.Title,
                    $"{alert.LogName} · {alert.Provider} · event {alert.EventId} / record {alert.RecordId?.ToString() ?? "unavailable"} · {alert.Technique}",
                    alert.Severity,
                    new SolidColorBrush(severityColor),
                    isEvidence ? "EVIDENCE" : "RELATED",
                    isEvidence));
            }

            EmptyState.Visibility = TimelineEvents.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
            StatusHeadline.Text = $"Showing {TimelineEvents.Count:N0} timeline events ({TimelineEvents.Count(e => e.IsEvidence)} evidence)";
            StatusDetail.Text = $"Time window: {timeWindowStart:HH:mm:ss} to {timeWindowEnd:HH:mm:ss} (±30 minutes around finding)";
        }
        finally
        {
            _requestInFlight = false;
        }
    }

    private void FilterBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var query = FilterBox?.Text?.Trim() ?? "";
        foreach (var row in TimelineEvents)
        {
            bool matches = query.Length == 0 ||
                row.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Evidence.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.AlertId.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.TimeLocal.Contains(query, StringComparison.OrdinalIgnoreCase);
            row.Visibility = matches ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
        }
    }

    private void ViewAlert_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string alertId }) return;
        // Navigate to Alerts page with the alert ID as a filter
        Frame.Navigate(typeof(AlertsPage), alertId);
    }
}

public sealed class TimelineEventRow : ObservableRow
{
    private string _alertId;
    private string _timeLocal;
    private string _title;
    private string _evidence;
    private string _severity;
    private SolidColorBrush _severityBrush;
    private string _category;
    private bool _isEvidence;
    private Microsoft.UI.Xaml.Visibility _visibility = Microsoft.UI.Xaml.Visibility.Visible;

    public TimelineEventRow(string alertId, string timeLocal, string title, string evidence, string severity,
        SolidColorBrush severityBrush, string category, bool isEvidence)
    {
        _alertId = alertId;
        _timeLocal = timeLocal;
        _title = title;
        _evidence = evidence;
        _severity = severity;
        _severityBrush = severityBrush;
        _category = category;
        _isEvidence = isEvidence;
    }

    public string AlertId { get => _alertId; private set => SetProperty(ref _alertId, value); }
    public string TimeLocal { get => _timeLocal; private set => SetProperty(ref _timeLocal, value); }
    public string Title { get => _title; private set => SetProperty(ref _title, value); }
    public string Evidence { get => _evidence; private set => SetProperty(ref _evidence, value); }
    public string Severity { get => _severity; private set => SetProperty(ref _severity, value); }
    public SolidColorBrush SeverityBrush { get => _severityBrush; private set => SetProperty(ref _severityBrush, value); }
    public string Category { get => _category; private set => SetProperty(ref _category, value); }
    public bool IsEvidence { get => _isEvidence; private set => SetProperty(ref _isEvidence, value); }
    public Microsoft.UI.Xaml.Visibility Visibility { get => _visibility; set => SetProperty(ref _visibility, value); }
}