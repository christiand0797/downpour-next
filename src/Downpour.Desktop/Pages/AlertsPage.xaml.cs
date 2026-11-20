using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace Downpour_Desktop.Pages;

public sealed partial class AlertsPage : Page
{
    private readonly SecurityAlertClient _client = new();
    private readonly DispatcherQueueTimer _refreshTimer;
    private IReadOnlyList<SecurityAlert> _allAlerts = [];
    private SecurityAlertSnapshot? _currentSnapshot;
    private bool _requestInFlight;
    private bool _stateChangeInFlight;
    private bool _exportInFlight;

    public LiveCollection<SecurityAlertRow> Alerts { get; } = [];
    public LiveCollection<CorrelationFindingRow> CorrelationFindings { get; } = [];
    public LiveCollection<RepeatGroupRow> RepeatGroups { get; } = [];
    public LiveCollection<SuppressionRow> Suppressions { get; } = [];

    public AlertsPage()
    {
        InitializeComponent();
        EntityDetails.Attach(AlertList, item => item is SecurityAlertRow { Source: { } a } ? DetailDescriptions.Alert(a) : null);
        EntityDetails.Attach(CorrelationList, item => item is CorrelationFindingRow c ? new DetailEntity(c.Title, $"Correlated incident · {c.Severity}",
            [new("Severity", c.Severity), new("Summary", c.Summary), new("Correlation ID", c.CorrelationId)], Kind: "incident") : null);
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

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        var snapshot = _currentSnapshot;
        if (_exportInFlight || snapshot is null) return;
        _exportInFlight = true;
        ExportButton.IsEnabled = false;
        try
        {
            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = $"Downpour-Investigation-{DateTimeOffset.Now:yyyyMMdd-HHmmss}"
            };
            picker.FileTypeChoices.Add("JSON investigation", new List<string> { ".json" });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            var file = await picker.PickSaveFileAsync();
            if (file is null)
            {
                StatusHeadline.Text = "Investigation export cancelled";
                return;
            }

            var json = AlertInvestigationExport.CreateJson(snapshot);
            await FileIO.WriteTextAsync(file, json);
            StatusHeadline.Text = "Investigation snapshot exported";
            StatusDetail.Text = $"Saved {snapshot.Alerts.Count:N0} bounded alert records as metadata-only JSON. Event bodies and user content are excluded.";
        }
        catch (Exception exception)
        {
            StatusHeadline.Text = "Investigation export failed";
            StatusDetail.Text = $"The report was not confirmed as saved ({exception.GetType().Name}). Choose another local destination and retry.";
        }
        finally
        {
            _exportInFlight = false;
            ExportButton.IsEnabled = _currentSnapshot is not null;
        }
    }

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
                _currentSnapshot = null;
                CorrelationFindings.Clear();
                RepeatGroups.Clear();
                Suppressions.Clear();
                RepeatCount.Text = "No repeated findings while the alert store is offline.";
                ExportButton.IsEnabled = false;
                AlertCount.Text = "ALERT STORE OFFLINE";
                ApplyFilters();
                return;
            }

            App.MarkSensorServiceConnected();
            _currentSnapshot = snapshot;
            ExportButton.IsEnabled = !_exportInFlight;
            _allAlerts = snapshot.Alerts;
            var correlated = AlertCorrelationEngine.Correlate(snapshot);

            CorrelationFindings.Clear();
            foreach (var finding in correlated)
            {
                CorrelationFindings.Add(new CorrelationFindingRow(finding));
            }

            // Presentation-only collapse of repeated source/subject pairs. The underlying alerts keep their identity so
            // every triage action above still applies to individual evidence.
            var groups = AlertGrouping.Group(snapshot.Alerts.Select(alert => new AlertGroupingInput(
                string.IsNullOrWhiteSpace(alert.LogName) ? "local alerts" : alert.LogName,
                alert.Title,
                SeverityRank(alert.Severity),
                alert.LastSeenUtc)));
            var repeated = groups.Where(group => group.Count > 1).Take(8).ToArray();
            RepeatGroups.Clear();
            foreach (var group in repeated) RepeatGroups.Add(new RepeatGroupRow(group));
            Suppressions.Clear();
            foreach (var suppression in snapshot.Suppressions ?? []) Suppressions.Add(new SuppressionRow(suppression));
            SuppressionCount.Text = Suppressions.Count == 0
                ? "No false-positive suppression is hiding anything."
                : $"{Suppressions.Count:N0} active suppression{(Suppressions.Count == 1 ? "" : "s")} · {Suppressions.Sum(row => row.Hidden):N0} hidden matches";
            var repeatedPairs = groups.Count(group => group.Count > 1);
            RepeatCount.Text = repeatedPairs == 0
                ? "No repeated source and subject pairs in this snapshot."
                : $"{repeatedPairs:N0} repeated pairs · {groups.Count - repeatedPairs:N0} single findings · showing the {repeated.Length} most severe";

            var openCount = snapshot.Alerts.Count(alert => alert.State == "Open");
            var notices = snapshot.Warnings.Distinct().ToArray();
            // Warnings are advisory (suppression state, freshness). Treating any warning as a storage failure mislabelled
            // routine notices as an outage.
            StatusHeadline.Text = notices.Length == 0
                ? "Local security alert monitor connected"
                : $"Local security alert monitor connected · {notices.Length} notice{(notices.Length == 1 ? "" : "s")}";
            StatusDetail.Text = notices.Length == 0
                ? $"Captured {snapshot.CapturedAtUtc.ToLocalTime():MMM d · HH:mm:ss}. {openCount:N0} open in the latest {snapshot.Alerts.Count:N0} of {snapshot.TotalCount:N0} retained alerts; retention is 30 days / 10,000 alerts."
                : string.Join("  •  ", notices);
            ApplyFilters(snapshot.TotalCount);
        }
        finally { _requestInFlight = false; }
    }

    private async void Acknowledge_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "Acknowledged");
    private async void Suppress_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "Suppressed");
    private async void Reopen_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "Open");
    private async void FalsePositive_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "FalsePositive");
    private async void RearmFalsePositive_Click(object sender, RoutedEventArgs e) => await ChangeStateFromButtonAsync(sender, "RearmFalsePositive");

    private async Task ChangeStateFromButtonAsync(object sender, string nextState)
    {
        if (_stateChangeInFlight || sender is not Button { Tag: string alertId }) return;
        var alert = _allAlerts.FirstOrDefault(candidate => candidate.AlertId == alertId);
        if (alert is null) return;

        _stateChangeInFlight = true;
        try
        {
            StatusHeadline.Text = nextState switch
            {
                "FalsePositive" => "Recording false-positive confirmation",
                "RearmFalsePositive" => "Re-arming matching alert rule",
                _ => $"Saving local triage state: {nextState}"
            };
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
                (StatusHeadline.Text, StatusDetail.Text) = response.ResultCode switch
                {
                    "confirmed-1" => ("False positive recorded · confirmation 1 of 3", "Only future matches of this exact channel/provider/event-ID rule can be auto-suppressed."),
                    "confirmed-2" => ("False positive recorded · confirmation 2 of 3", "A third explicit confirmation is required before matching alerts are suppressed."),
                    "fingerprint-suppressed" => ("Matching alert rule suppressed", "Three false-positive confirmations were recorded. Re-arm any matching row to remove the rule."),
                    "rearmed" => ("Matching alert rule re-armed", "The false-positive suppression was cleared and its suppressed alerts were reopened."),
                    "updated" => ("Local triage state saved", "Only local alert review state changed. No operating-system setting or process was touched."),
                    _ => ("Alert state is already current", "Only local alert review state changed. No operating-system setting or process was touched.")
                };
            }
            await RefreshAsync();
        }
        finally { _stateChangeInFlight = false; }
    }

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        _ => 1,
    };

    private async void RearmSuppression_Click(object sender, RoutedEventArgs e)
    {
        if (_stateChangeInFlight || sender is not Button { Tag: string alertId } || string.IsNullOrEmpty(alertId)) return;
        _stateChangeInFlight = true;
        try
        {
            var response = await _client.ChangeStateAsync(
                new AlertStateChangeRequest(1, Guid.NewGuid(), alertId, "Suppressed", "RearmFalsePositive"));
            StatusHeadline.Text = response is null ? "Local triage pipe unavailable"
                : response.Accepted ? "Suppression re-armed" : "Suppression could not be re-armed";
            StatusDetail.Text = response is null
                ? "No change was confirmed. Refresh the alert list before retrying."
                : $"Result: {response.ResultCode}. Re-arming clears the rule, reopens its suppressed alerts and stops hiding new matches.";
            await RefreshAsync();
        }
        finally { _stateChangeInFlight = false; }
    }

    private void RepeatGroup_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string subject }) return;
        SearchBox.Text = subject;
        ApplyFilters();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilters();
    private void StateFilter_SelectionChanged(object sender, SelectionChangedEventArgs e) => ApplyFilters();

    private void AlertList_ItemClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is not SecurityAlertRow { Source: { } alert }) return;
        ExplanationTitle.Text = alert.Title;
        ExplanationText.Text = AlertExplanation.ForAlert(alert);
        ExplanationPanel.Visibility = Visibility.Visible;
    }

    private void CloseExplanation_Click(object sender, RoutedEventArgs e) => ExplanationPanel.Visibility = Visibility.Collapsed;

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
            SecurityFindingCatalog.IsFinding(alert.LogName)
                ? $"{TriageRow.SourceLabel(alert)} finding · {alert.Technique}{(alert.IsVerified ? " · verified" : "")}"
                : $"{alert.LogName} · {alert.Provider} · event {alert.EventId} / record {alert.RecordId?.ToString() ?? "unavailable"} · {alert.Technique}",
            alert.Severity, new SolidColorBrush(severityColor), alert.State, new SolidColorBrush(stateColor),
            alert.Occurrences == 1 ? "1 occurrence" : $"{alert.Occurrences:N0} occurrences",
            alert.State == "Open", alert.State == "Open", alert.State != "Open") { Source = alert };
    }

    private void CorrelationList_ViewTimeline_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string correlationId }) return;
        Frame.Navigate(typeof(InvestigationTimelinePage), correlationId);
    }
}

public sealed class SuppressionRow(AlertSuppression suppression)
{
    public string Title { get; } = suppression.Title;
    public string AlertId { get; } = suppression.AlertId ?? "";
    public int Hidden { get; } = suppression.MatchesSinceGrant;
    public bool CanRearm { get; } = !string.IsNullOrEmpty(suppression.AlertId);
    public bool IsExpired { get; } = suppression.ExpiresUtc is { } expires && expires <= DateTimeOffset.UtcNow;
    public string Meta { get; } = BuildMeta(suppression);
    public SolidColorBrush Brush { get; } = new((suppression.ExpiresUtc is { } expires && expires <= DateTimeOffset.UtcNow)
        ? Color.FromArgb(255, 255, 167, 82)
        : Color.FromArgb(255, 86, 210, 235));

    private static string BuildMeta(AlertSuppression suppression)
    {
        var hidden = suppression.MatchesSinceGrant == 1 ? "1 match hidden" : $"{suppression.MatchesSinceGrant:N0} matches hidden";
        var expiry = suppression.ExpiresUtc is not { } expires ? "no expiry recorded"
            : expires <= DateTimeOffset.UtcNow ? $"expired {expires.ToLocalTime():yyyy-MM-dd}"
            : $"expires {expires.ToLocalTime():yyyy-MM-dd}";
        return $"{suppression.LogName} · {suppression.Confirmations} confirmations · {hidden} · {expiry}";
    }
}

public sealed class RepeatGroupRow(AlertGroup group)
{
    private static readonly SolidColorBrush Critical = new(Color.FromArgb(255, 255, 86, 121));
    private static readonly SolidColorBrush High = new(Color.FromArgb(255, 255, 167, 82));
    private static readonly SolidColorBrush Medium = new(Color.FromArgb(255, 255, 218, 119));
    private static readonly SolidColorBrush Other = new(Color.FromArgb(255, 86, 210, 235));

    public string Subject { get; } = group.Subject;
    public string Source { get; } = group.Source;
    public string Count { get; } = group.Count == 1 ? "1 alert" : $"{group.Count:N0} alerts";
    public string Span { get; } = $"{group.FirstSeenUtc.ToLocalTime():MMM d HH:mm} → {group.LastSeenUtc.ToLocalTime():HH:mm}";
    public string Meta { get; } = $"{group.Source}  ·  {(group.Count == 1 ? "1 alert" : $"{group.Count:N0} alerts")}  ·  {group.FirstSeenUtc.ToLocalTime():MMM d HH:mm} → {group.LastSeenUtc.ToLocalTime():HH:mm}";
    public string Severity { get; } = group.HighestSeverityRank switch
    {
        >= 4 => "CRITICAL",
        3 => "HIGH",
        2 => "MEDIUM",
        _ => "LOW",
    };
    public SolidColorBrush SeverityBrush { get; } = group.HighestSeverityRank switch
    {
        >= 4 => Critical,
        3 => High,
        2 => Medium,
        _ => Other,
    };
}

public sealed class CorrelationFindingRow : ObservableRow
{
    private CorrelatedAlertFinding _finding;
    private string _severity;
    private SolidColorBrush _severityBrush;
    private string _summary;

    public CorrelationFindingRow(CorrelatedAlertFinding finding)
    {
        _finding = finding;
        _severity = finding.Severity;
        _severityBrush = finding.Severity switch
        {
            "CRITICAL" => new SolidColorBrush(Color.FromArgb(255, 255, 86, 121)),
            "HIGH" => new SolidColorBrush(Color.FromArgb(255, 255, 167, 82)),
            "MEDIUM" => new SolidColorBrush(Color.FromArgb(255, 255, 218, 119)),
            _ => new SolidColorBrush(Color.FromArgb(255, 86, 210, 235))
        };
        _summary = finding.EvidenceSummary;
    }

    public CorrelatedAlertFinding Finding => _finding;
    public string Title => _finding.Title;
    public string Summary => _summary;
    public string Severity => _severity;
    public SolidColorBrush SeverityBrush => _severityBrush;
    public string CorrelationId => _finding.CorrelationId;
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
    public SecurityAlert? Source { get; set; }
}