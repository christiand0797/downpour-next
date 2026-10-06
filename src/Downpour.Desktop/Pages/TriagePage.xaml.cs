using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using Windows.UI;

namespace Downpour_Desktop.Pages;

/// <summary>
/// v29 Threats and Possible Threats over the local alert store. Threats are CRITICAL/HIGH or user-verified items;
/// Possible Threats are the remaining open items awaiting verification. Response actions (kill, quarantine, block,
/// isolate) are not offered until the audited action broker exists.
/// </summary>
public sealed partial class TriagePage : Page
{
    public const string ThreatsMode = "threats";
    public const string PossibleMode = "possible-threats";

    private readonly SecurityAlertClient _client = new();
    private IReadOnlyList<SecurityAlert> _alerts = [];
    private string _mode = ThreatsMode;
    private bool _busy;

    public ObservableCollection<TriageRow> Items { get; } = [];

    public string Mode => _mode;

    public TriagePage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _mode = e.Parameter as string == PossibleMode ? PossibleMode : ThreatsMode;
        var threats = _mode == ThreatsMode;
        Breadcrumb.Text = threats ? "DOWNPOUR  /  TRIAGE  /  THREATS" : "DOWNPOUR  /  TRIAGE  /  POSSIBLE THREATS";
        PageTitle.Text = threats ? "Threats" : "Possible threats";
        PageDescription.Text = threats
            ? "High-severity detections and items you verified, from Windows events, hardening posture, firewall, and persistence review."
            : "Lower-severity detections awaiting verification. Verify moves an item to Threats; dismiss or mark a false positive to clear it.";
        Footnote.Text = threats
            ? "Response actions from v29 (remediate, quarantine, kill, block IP, isolate host, auto-remediation) are not available: they need the audited action broker (DN-008). Triage changes only Downpour's local review state."
            : "In v29 this list had no producer and was always empty. Here it is fed by the same alert store as Threats. Triage changes only Downpour's local review state.";
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();
    private void Filter_Changed(object sender, object e) => ApplyFilter();
    private async void Verify_Click(object sender, RoutedEventArgs e) => await ChangeAsync(sender, "Verify");
    private async void Unverify_Click(object sender, RoutedEventArgs e) => await ChangeAsync(sender, "Unverify");
    private async void FalsePositive_Click(object sender, RoutedEventArgs e) => await ChangeAsync(sender, "FalsePositive");
    private async void Dismiss_Click(object sender, RoutedEventArgs e) => await ChangeAsync(sender, "Suppressed");
    private async void Reopen_Click(object sender, RoutedEventArgs e) => await ChangeAsync(sender, "Open");

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string id } || _alerts.FirstOrDefault(alert => alert.AlertId == id) is not { } alert) return;
        var package = new DataPackage();
        package.SetText(TriageRow.Describe(alert));
        Clipboard.SetContent(package);
        StatusHeadline.Text = "Details copied";
    }

    private async Task RefreshAsync()
    {
        var snapshot = await _client.TryGetSnapshotAsync();
        if (snapshot is null)
        {
            await App.EnsureSensorServiceAsync();
            snapshot = await _client.TryGetSnapshotAsync();
        }
        if (snapshot is null)
        {
            _alerts = [];
            ApplyFilter();
            StatusHeadline.Text = "Downpour is running · alert store offline";
            StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted alerts are shown.";
            return;
        }
        App.MarkSensorServiceConnected();
        _alerts = snapshot.Alerts;
        ApplyFilter();
        var active = _alerts.Where(alert => alert.State != "Suppressed").ToArray();
        var threats = active.Count(SecurityFindingCatalog.IsThreat);
        StatusHeadline.Text = $"{threats} threat{(threats == 1 ? "" : "s")} · {active.Length - threats} possible · {_alerts.Count - active.Length} dismissed";
        StatusDetail.Text = $"Updated {snapshot.CapturedAtUtc.ToLocalTime():HH:mm:ss}. Hardening, firewall, and persistence findings are re-checked every 10 minutes.";
    }

    private void ApplyFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        var source = SourceFilter?.SelectedIndex switch
        {
            1 => "events", 2 => SecurityFindingCatalog.Hardening, 3 => SecurityFindingCatalog.Firewall, 4 => SecurityFindingCatalog.Persistence, _ => null
        };
        var showDismissed = ShowDismissed?.IsChecked == true;
        var matches = _alerts.Where(alert =>
                SecurityFindingCatalog.IsThreat(alert) == (_mode == ThreatsMode)
                && (showDismissed || alert.State != "Suppressed")
                && (source is null || (source == "events" ? !SecurityFindingCatalog.IsFinding(alert.LogName) : alert.LogName == source))
                && (query.Length == 0 || new[] { alert.Title, alert.LogName, alert.Technique, alert.Provider }.Any(value => value.Contains(query, StringComparison.OrdinalIgnoreCase))))
            .OrderBy(alert => alert.State == "Suppressed")
            .ThenBy(alert => alert.Severity switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3 })
            .ThenByDescending(alert => alert.LastSeenUtc)
            .ToArray();
        Items.Clear();
        foreach (var alert in matches) Items.Add(new TriageRow(alert));
        if (EmptyState is not null)
        {
            EmptyState.Text = _mode == ThreatsMode ? "No threats match." : "No possible threats are waiting for verification.";
            EmptyState.Visibility = Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private async Task ChangeAsync(object sender, string next)
    {
        if (_busy || sender is not Button { Tag: string id } || _alerts.FirstOrDefault(alert => alert.AlertId == id) is not { } alert) return;
        _busy = true;
        try
        {
            var response = await _client.ChangeStateAsync(new AlertStateChangeRequest(1, Guid.NewGuid(), alert.AlertId, alert.State, next));
            (StatusHeadline.Text, StatusDetail.Text) = response switch
            {
                null => ("Local triage pipe unavailable", "No change was confirmed. Refresh before retrying."),
                { Accepted: false } => ("Request was rejected", $"Result: {response.ResultCode}. The item may have changed; refresh and retry."),
                { ResultCode: "verified" } => ("Verified and moved to Threats", "Only Downpour's local review state changed."),
                { ResultCode: "unverified" } => ("Moved back to Possible Threats", "Only Downpour's local review state changed."),
                { ResultCode: "confirmed-1" or "confirmed-2" } => ($"False positive recorded · {response.ResultCode[^1]} of 3", "This exact finding is suppressed automatically after three confirmations."),
                { ResultCode: "fingerprint-suppressed" } => ("False positive suppressed", "This finding will stay suppressed when it is detected again. Re-arm it from the Alerts page."),
                _ => ("Local triage state saved", "Only Downpour's local review state changed. No system setting or process was touched.")
            };
            await RefreshAsync();
        }
        finally { _busy = false; }
    }
}

public sealed class TriageRow(SecurityAlert alert)
{
    public string AlertId => alert.AlertId;
    public string Severity => alert.Severity;
    public string Title => alert.Title;
    public string StateLabel => alert.State == "Suppressed" ? "Dismissed" : alert.IsVerified ? "Verified" : alert.State;
    public string Detail => $"{SourceLabel(alert)} · {alert.Technique} · first {alert.FirstSeenUtc.ToLocalTime():MM-dd HH:mm} · last {alert.LastSeenUtc.ToLocalTime():MM-dd HH:mm}" +
        (alert.Occurrences > 1 ? $" · ×{alert.Occurrences}" : "");
    public bool CanTriage => alert.State is "Open" or "Acknowledged";
    public Visibility VerifyVisibility => CanTriage && !alert.IsVerified && !SecurityFindingCatalog.IsThreat(alert) ? Visibility.Visible : Visibility.Collapsed;
    public Visibility UnverifyVisibility => alert.IsVerified ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ReopenVisibility => alert.State == "Suppressed" ? Visibility.Visible : Visibility.Collapsed;
    public SolidColorBrush SeverityBrush => new(alert.Severity switch
    {
        "CRITICAL" or "HIGH" => Color.FromArgb(255, 255, 120, 110),
        "MEDIUM" => Color.FromArgb(255, 255, 170, 90),
        _ => Color.FromArgb(255, 255, 214, 102)
    });

    internal static string SourceLabel(SecurityAlert alert) => alert.LogName switch
    {
        SecurityFindingCatalog.Hardening => "Hardening",
        SecurityFindingCatalog.Firewall => "Firewall",
        SecurityFindingCatalog.Persistence => "Persistence",
        _ => $"{alert.LogName} event {alert.EventId}"
    };

    internal static string Describe(SecurityAlert alert) =>
        $"{alert.Severity} | {alert.Title} | {SourceLabel(alert)} | {alert.Technique} | state {alert.State}{(alert.IsVerified ? " (verified)" : "")} | first {alert.FirstSeenUtc:O} | last {alert.LastSeenUtc:O}";
}
