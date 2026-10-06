using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class FirewallPage : Page
{
    private readonly FirewallInventoryClient _client = new();
    private IReadOnlyList<FirewallRuleEntry> _rules = [];
    private bool _requestInFlight;

    public ObservableCollection<FirewallProfileRow> Profiles { get; } = [];
    public ObservableCollection<FirewallFindingRow> Findings { get; } = [];
    public ObservableCollection<FirewallRuleRow> Rules { get; } = [];
    public ObservableCollection<FirewallBlockedRow> Blocked { get; } = [];

    public FirewallPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private void Filter_Changed(object sender, object e) => ApplyFilter();

    private async Task RefreshAsync()
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        RefreshButton.IsEnabled = false;
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            Profiles.Clear();
            Findings.Clear();
            Blocked.Clear();
            if (snapshot is null)
            {
                _rules = [];
                ApplyFilter();
                StatusHeadline.Text = "Downpour is running · firewall sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted firewall data is shown.";
                BlockedStatus.Text = "";
                return;
            }

            App.MarkSensorServiceConnected();
            foreach (var profile in snapshot.Profiles) Profiles.Add(new FirewallProfileRow(profile));
            foreach (var finding in snapshot.Findings.OrderBy(finding => finding.Severity switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3 }))
                Findings.Add(new FirewallFindingRow(finding));
            NoFindings.Visibility = Findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            foreach (var blocked in snapshot.BlockedConnections) Blocked.Add(new FirewallBlockedRow(blocked));
            _rules = snapshot.Rules;
            ApplyFilter();

            var downpourRules = snapshot.Rules.Count(rule => rule.IsDownpourRule);
            StatusHeadline.Text = $"Firewall service {snapshot.ServiceState.ToLowerInvariant()} · {snapshot.RuleCount:N0} rules · {snapshot.Findings.Count} finding{(snapshot.Findings.Count == 1 ? "" : "s")}";
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"Captured {snapshot.CapturedAtUtc.ToLocalTime():HH:mm:ss}. {downpourRules:N0} rule{(downpourRules == 1 ? "" : "s")} created by Downpour v29 (name starts with \"downpour\").{warnings}";
            BlockedStatus.Text = snapshot.BlockedEventsStatus switch
            {
                FirewallBlockedEventsStatuses.Available => $"{snapshot.BlockedConnections.Count} most recent blocked connections.",
                FirewallBlockedEventsStatuses.NoEvents => "No 5157 events. Windows only records them when \"Audit Filtering Platform Connection\" failure auditing is enabled.",
                FirewallBlockedEventsStatuses.AccessDenied => "The Security log requires administrator rights or Event Log Readers membership; blocked connections are not shown.",
                _ => "The Security log could not be queried."
            };
        }
        finally
        {
            _requestInFlight = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private void ApplyFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        var direction = DirectionFilter?.SelectedIndex switch { 1 => "Inbound", 2 => "Outbound", _ => null };
        var action = ActionFilter?.SelectedIndex switch { 1 => "Allow", 2 => "Block", _ => null };
        var enabledOnly = EnabledOnly?.IsChecked == true;
        var downpourOnly = DownpourOnly?.IsChecked == true;
        var matches = _rules.Where(rule =>
                (direction is null || rule.Direction == direction)
                && (action is null || rule.Action == action)
                && (!enabledOnly || rule.Enabled)
                && (!downpourOnly || rule.IsDownpourRule)
                && (query.Length == 0 || new[] { rule.Name, rule.LocalPorts, rule.Application, rule.Grouping, rule.RemoteAddresses }
                    .Any(value => value.Contains(query, StringComparison.OrdinalIgnoreCase))))
            .OrderBy(rule => rule.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        Rules.Clear();
        foreach (var rule in matches) Rules.Add(new FirewallRuleRow(rule));
        if (RuleCount is not null) RuleCount.Text = $"{matches.Length:N0} of {_rules.Count:N0} rules";
    }
}

public sealed class FirewallProfileRow(FirewallProfileState profile)
{
    public string Title => profile.IsActive ? $"{profile.Profile} (active)" : profile.Profile;
    public string StateText => profile.Enabled switch { true => "On", false => "Off", null => "Unknown" };
    public string Defaults => $"Inbound {profile.DefaultInboundAction.ToLowerInvariant()} · outbound {profile.DefaultOutboundAction.ToLowerInvariant()}";
    public SolidColorBrush Accent => new(profile.Enabled switch
    {
        true => Color.FromArgb(255, 120, 230, 160),
        false => Color.FromArgb(255, 255, 120, 110),
        null => Color.FromArgb(255, 255, 214, 102)
    });
}

public sealed class FirewallFindingRow(FirewallFinding finding)
{
    public string Severity => finding.Severity;
    public string Summary => finding.Summary;
    public SolidColorBrush SeverityBrush => new(finding.Severity switch
    {
        "CRITICAL" or "HIGH" => Color.FromArgb(255, 255, 120, 110),
        "MEDIUM" => Color.FromArgb(255, 255, 170, 90),
        _ => Color.FromArgb(255, 255, 214, 102)
    });
}

public sealed class FirewallRuleRow(FirewallRuleEntry rule)
{
    public string Name => rule.IsDownpourRule ? $"{rule.Name}  · Downpour" : rule.Name;
    public string Application => rule.Application.Length > 0 ? rule.Application : rule.Grouping;
    public string Direction => rule.Enabled ? rule.Direction : $"{rule.Direction} (off)";
    public string Action => rule.Action;
    public string Protocol => rule.Protocol;
    public string Ports => rule.LocalPorts.Length > 0 ? rule.LocalPorts : "*";
    public string Scope => $"{rule.Profiles} · {(rule.RemoteAddresses.Length > 0 ? rule.RemoteAddresses : "*")}";
    public SolidColorBrush ActionBrush => new(rule.Action == "Block" ? Color.FromArgb(255, 255, 150, 120) : Color.FromArgb(255, 120, 230, 160));
}

public sealed class FirewallBlockedRow(FirewallBlockedConnection blocked)
{
    public string Time => blocked.TimeUtc == DateTimeOffset.MinValue ? "unknown" : blocked.TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");
    public string Direction => blocked.Direction;
    public string Application => blocked.Application;
    public string Endpoints => $"{blocked.SourceAddress} → {blocked.DestinationAddress}:{blocked.DestinationPort}";
    public string Protocol => blocked.Protocol;
}
