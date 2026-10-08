using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class PersistencePage : Page
{
    private const string AllCategories = "All categories";
    private readonly PersistenceInventoryClient _client = new();
    private IReadOnlyList<PersistenceEntry> _entries = [];
    private bool _requestInFlight;

    public LiveCollection<PersistenceFindingRow> Findings { get; } = [];
    public LiveCollection<PersistenceEntryRow> Entries { get; } = [];

    private readonly BreakdownChart _categoryChart = new() { Title = "Autostart items by type", Subtitle = "Everything that starts automatically" };
    private readonly BreakdownChart _changeChart = new() { Title = "Changes this week", Subtitle = "Compared with the first baseline" };
    private readonly BreakdownChart _findingChart = new() { Title = "Findings by severity", Subtitle = "Signer-aware; signed vendor items rank low" };

    public PersistencePage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _categoryChart, _changeChart, _findingChart);
        LiveRefresh.Attach(this, () => RefreshAsync(quiet: true));
        CategoryFilter.Items.Add(AllCategories);
        foreach (var category in new[]
        {
            PersistenceCategories.RegistryRun, PersistenceCategories.Winlogon, PersistenceCategories.StartupFolder,
            PersistenceCategories.ScheduledTask, PersistenceCategories.WmiSubscription, PersistenceCategories.DllShadow,
            PersistenceCategories.DriverFile
        })
            CategoryFilter.Items.Add(category);
        CategoryFilter.SelectedIndex = 0;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private void Filter_Changed(object sender, object e) => ApplyFilter();

    private async Task RefreshAsync(bool quiet = false)
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        if (!quiet) RefreshButton.IsEnabled = false;
        if (!quiet) StatusHeadline.Text = "Scanning autostart locations";
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            Findings.Clear();
            if (snapshot is null)
            {
                _entries = [];
                ApplyFilter();
                StatusHeadline.Text = "Downpour is running · persistence sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted inventory is shown.";
                NoFindings.Visibility = Visibility.Collapsed;
                return;
            }

            App.MarkSensorServiceConnected();
            foreach (var finding in snapshot.Findings.OrderBy(finding => finding.Severity switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3 }))
                Findings.Add(new PersistenceFindingRow(finding));
            NoFindings.Text = snapshot.IsFirstBaseline
                ? "Baseline created on this scan. Items added or changed from now on will be reported."
                : "No persistence findings.";
            NoFindings.Visibility = Findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            _entries = snapshot.Entries;
            _categoryChart.SetData(snapshot.Entries.Where(e => e.Category != PersistenceCategories.DriverFile || e.Change != PersistenceChanges.Baseline)
                .GroupBy(e => e.Category).Select(g => (g.Key, (double)g.Count())));
            _changeChart.SetData(snapshot.Entries.GroupBy(e => e.Change).Select(g => (g.Key, (double)g.Count())),
                new Dictionary<string, Windows.UI.Color> { [PersistenceChanges.New] = HudPalette.Warning, [PersistenceChanges.Modified] = HudPalette.Serious, [PersistenceChanges.Baseline] = HudPalette.Other });
            _findingChart.SetData(snapshot.Findings.GroupBy(f => f.Severity, StringComparer.OrdinalIgnoreCase).Select(g => (g.Key, (double)g.Count())));
            ApplyFilter();

            var recent = snapshot.Entries.Count(entry => entry.Change != PersistenceChanges.Baseline);
            StatusHeadline.Text = $"{snapshot.Entries.Count:N0} autostart items · {recent} new or changed · {snapshot.Findings.Count} finding{(snapshot.Findings.Count == 1 ? "" : "s")}";
            var baseline = snapshot.BaselineCreatedAtUtc is { } created ? $"Baseline since {created.ToLocalTime():yyyy-MM-dd HH:mm}." : "";
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"{baseline} {string.Join(" · ", snapshot.SourceStatus)}.{warnings}";
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
        var category = CategoryFilter?.SelectedItem as string;
        var recentOnly = RecentOnly?.IsChecked == true;
        var matches = _entries.Where(entry =>
                (category is null || category == AllCategories || entry.Category == category)
                && (!recentOnly || entry.Change != PersistenceChanges.Baseline)
                && (query.Length == 0 || new[] { entry.Name, entry.Location, entry.Value }.Any(value => value.Contains(query, StringComparison.OrdinalIgnoreCase))))
            .OrderBy(entry => entry.Change == PersistenceChanges.Baseline)
            .ThenBy(entry => entry.Category, StringComparer.Ordinal)
            .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        Entries.Clear();
        foreach (var entry in matches) Entries.Add(new PersistenceEntryRow(entry));
        if (EntryCount is not null) EntryCount.Text = $"{matches.Length:N0} of {_entries.Count:N0} items";
    }
}

public sealed class PersistenceFindingRow(PersistenceFinding finding)
{
    public string Severity => finding.Severity;
    public string Summary => finding.Summary;
    public string Indicator => finding.Indicator;
    public string Technique => finding.Technique;
    public SolidColorBrush SeverityBrush => new(finding.Severity switch
    {
        "CRITICAL" or "HIGH" => Color.FromArgb(255, 255, 120, 110),
        "MEDIUM" => Color.FromArgb(255, 255, 170, 90),
        _ => Color.FromArgb(255, 255, 214, 102)
    });
}

public sealed class PersistenceEntryRow(PersistenceEntry entry)
{
    public string Category => entry.Category;
    public string Name => entry.Name;
    public string Value => entry.Value;
    public string Location => entry.Location;
    public string Indicators => string.Join(" · ", entry.Indicators);
    public Visibility IndicatorsVisibility => entry.Indicators.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
    public string Change => entry.Change switch
    {
        PersistenceChanges.New => $"New {entry.ChangedAtUtc?.ToLocalTime():MM-dd}",
        PersistenceChanges.Modified => $"Changed {entry.ChangedAtUtc?.ToLocalTime():MM-dd}",
        _ => ""
    };
    public SolidColorBrush ChangeBrush => new(entry.Change == PersistenceChanges.Modified
        ? Color.FromArgb(255, 255, 170, 90)
        : Color.FromArgb(255, 120, 200, 255));
}
