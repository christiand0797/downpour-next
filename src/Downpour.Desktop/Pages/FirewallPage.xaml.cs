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
    private readonly FirewallActionClient _actionClient = new();
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
                CleanupLegacyButton.Visibility = Visibility.Collapsed;
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

            var legacyRules = snapshot.Rules.Count(rule => rule.IsDownpourRule && !rule.Name.StartsWith("DownpourNext_", StringComparison.OrdinalIgnoreCase));
            var nextRules = snapshot.Rules.Count(rule => rule.Name.StartsWith("DownpourNext_", StringComparison.OrdinalIgnoreCase));
            CleanupLegacyButton.Visibility = legacyRules > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (legacyRules > 0)
            {
                CleanupLegacyButton.Content = $"Clean Up Legacy Rules ({legacyRules:N0})";
            }
            StatusHeadline.Text = $"Firewall service {snapshot.ServiceState.ToLowerInvariant()} · {snapshot.RuleCount:N0} rules · {snapshot.Findings.Count} finding{(snapshot.Findings.Count == 1 ? "" : "s")}";
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"Captured {snapshot.CapturedAtUtc.ToLocalTime():HH:mm:ss}. {nextRules:N0} active Downpour Next rule{(nextRules == 1 ? "" : "s")}, {legacyRules:N0} legacy v29 rule{(legacyRules == 1 ? "" : "s")}.{warnings}";
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

    private async void BlockIp_Click(object sender, RoutedEventArgs e)
    {
        var ipBox = new TextBox { PlaceholderText = "e.g. 198.51.100.1 or 2001:db8::1" };
        var durationCombo = new ComboBox
        {
            ItemsSource = new[] { "1 hour (60 min)", "24 hours (1440 min)", "7 days (10080 min)", "Permanent" },
            SelectedIndex = 1
        };
        var reasonBox = new TextBox { PlaceholderText = "Optional reason (e.g. C2 botnet host, port scan)" };

        var dialog = new ContentDialog
        {
            Title = "Block Remote IP (DN-008 Phase 3)",
            Content = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new TextBlock { Text = "Enter a specific remote IP address to block. System and private addresses (loopback, gateway, DNS servers, broadcast, and host adapter) are strictly protected to prevent network lockout.", TextWrapping = TextWrapping.Wrap },
                    new TextBlock { Text = "Remote IP Address:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    ipBox,
                    new TextBlock { Text = "Block Duration:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    durationCombo,
                    new TextBlock { Text = "Reason:", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                    reasonBox
                }
            },
            PrimaryButtonText = "Inspect & Preview",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = this.XamlRoot
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

        var ip = ipBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(ip)) return;

        int durationMinutes = durationCombo.SelectedIndex switch
        {
            0 => 60,
            1 => 1440,
            2 => 10080,
            3 => 0,
            _ => 1440
        };

        var reason = reasonBox.Text.Trim();

        var preview = await _actionClient.PreviewBlockIpAsync(ip, durationMinutes, reason);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await _actionClient.PreviewBlockIpAsync(ip, durationMinutes, reason);
        }

        if (preview is null)
        {
            var unreachDialog = new ContentDialog
            {
                Title = "Service Unreachable",
                Content = "The firewall action service endpoint is not reachable.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await unreachDialog.ShowAsync();
            return;
        }

        if (!preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Block Denied",
                Content = preview.Message,
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Target IP: {p.TargetIp}\n" +
                          $"Duration: {(p.DurationMinutes > 0 ? $"{p.DurationMinutes} minutes" : "Permanent")}\n\n" +
                          $"Rules to Create:\n• {string.Join("\n• ", p.RulesAffected)}\n\n" +
                          $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Are you sure you want to block this remote IP?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm Firewall Remote IP Block",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "Block IP",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary && p.ConsentToken is not null)
        {
            var outcome = await _actionClient.BlockIpAsync(p.TargetIp!, p.ConsentToken, p.DurationMinutes, reason);
            var outcomeDialog = new ContentDialog
            {
                Title = outcome?.Accepted == true ? "Firewall Rules Created" : "Block Failed",
                Content = outcome?.Message ?? "No response received from action service.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await outcomeDialog.ShowAsync();
            await RefreshAsync();
        }
    }

    private async void CleanupLegacy_Click(object sender, RoutedEventArgs e)
    {
        var preview = await _actionClient.PreviewCleanupLegacyAsync();
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await _actionClient.PreviewCleanupLegacyAsync();
        }

        if (preview is null || !preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Cleanup Unavailable",
                Content = preview?.Message ?? "The firewall action service is unreachable.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Remove all legacy Downpour v29 firewall rules?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm Legacy Rules Cleanup (DN-008 Phase 3)",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "Clean Up All Legacy Rules",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary && p.ConsentToken is not null)
        {
            var outcome = await _actionClient.CleanupLegacyAsync(p.ConsentToken);
            var outcomeDialog = new ContentDialog
            {
                Title = outcome?.Accepted == true ? "Legacy Rules Removed" : "Cleanup Failed",
                Content = outcome?.Message ?? "No response received from action service.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await outcomeDialog.ShowAsync();
            await RefreshAsync();
        }
    }

    private async void RemoveRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string ruleName || string.IsNullOrWhiteSpace(ruleName))
            return;

        var preview = await _actionClient.PreviewRemoveRuleAsync(ruleName);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await _actionClient.PreviewRemoveRuleAsync(ruleName);
        }

        if (preview is null || !preview.Accepted || preview.Preview is null)
        {
            var deniedDialog = new ContentDialog
            {
                Title = "Rule Removal Denied",
                Content = preview?.Message ?? "The firewall action service is unreachable.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await deniedDialog.ShowAsync();
            return;
        }

        var p = preview.Preview;
        var detailsText = $"Rule Name: {ruleName}\n\n" +
                          $"Expected Effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\n" +
                          $"Risks:\n• {string.Join("\n• ", p.Risks)}\n\n" +
                          "Consent token minted (valid for 60 seconds). Remove this firewall rule?";

        var confirmDialog = new ContentDialog
        {
            Title = "Confirm Rule Removal",
            Content = new TextBlock { Text = detailsText, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = "Remove Rule",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot
        };

        if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary && p.ConsentToken is not null)
        {
            var outcome = await _actionClient.RemoveRuleAsync(ruleName, p.ConsentToken);
            var outcomeDialog = new ContentDialog
            {
                Title = outcome?.Accepted == true ? "Rule Removed" : "Removal Failed",
                Content = outcome?.Message ?? "No response received from action service.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await outcomeDialog.ShowAsync();
            await RefreshAsync();
        }
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
    public string RawRuleName => rule.Name;
    public Visibility RemoveButtonVisibility => (rule.IsDownpourRule || rule.Name.StartsWith("DownpourNext_", StringComparison.OrdinalIgnoreCase)) ? Visibility.Visible : Visibility.Collapsed;
    public string Name => rule.Name.StartsWith("DownpourNext_", StringComparison.OrdinalIgnoreCase) ? $"{rule.Name}  · Downpour Next" : rule.IsDownpourRule ? $"{rule.Name}  · Downpour (v29)" : rule.Name;
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
