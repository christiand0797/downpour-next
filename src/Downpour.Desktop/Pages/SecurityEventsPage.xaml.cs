using System.Collections.ObjectModel;
using System.Globalization;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class SecurityEventsPage : Page
{
    private readonly SecurityEventClient _client = new();
    private readonly DispatcherQueueTimer _refreshTimer;
    private IReadOnlyList<SecurityEventObservation> _observations = [];
    private bool _requestInFlight;

    public ObservableCollection<SecurityEventRow> Events { get; } = [];

    private readonly BreakdownChart _severityChart = new() { Title = "Severity", Subtitle = "Observations in the 24-hour lookback" };
    private readonly TopBarsChart _channelChart = new() { Title = "By event channel", Subtitle = "Which Windows logs the observations came from" };
    private readonly TopBarsChart _kindChart = new() { Title = "Most frequent", Subtitle = "Event types by number of occurrences" };

    private static string ChannelLabel(string logName)
    {
        var name = logName.Replace("Microsoft-Windows-", "", StringComparison.OrdinalIgnoreCase);
        return name.Length <= 34 ? name : name[..34];
    }

    public SecurityEventsPage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _severityChart, _channelChart, _kindChart);
        _refreshTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _refreshTimer.Interval = TimeSpan.FromSeconds(1);
        _refreshTimer.IsRepeating = true;
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _refreshTimer.Start();
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
                StatusHeadline.Text = "Downpour is running · Windows event sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No event data is substituted.";
                _observations = [];
                SourceWarnings.Text = "Event source status unavailable.";
                ApplyFilters();
                return;
            }

            App.MarkSensorServiceConnected();
            _observations = snapshot.Events;
            _severityChart.SetData(snapshot.Events.GroupBy(e => e.Severity, StringComparer.OrdinalIgnoreCase).Select(g => (g.Key, (double)g.Sum(e => e.Occurrences))));
            _channelChart.SetData(snapshot.Events.GroupBy(e => ChannelLabel(e.LogName)).Select(g => (g.Key, (double)g.Sum(e => e.Occurrences))), "", HudPalette.Categorical[1]);
            _kindChart.SetData(snapshot.Events.GroupBy(e => $"{e.Summary} ({e.EventId})").Select(g => (g.Key, (double)g.Sum(e => e.Occurrences))), "", HudPalette.Categorical[3]);
            StatusHeadline.Text = $"Event source connected · {snapshot.Events.Count:N0} observations in the 24-hour lookback";
            StatusDetail.Text = snapshot.SourcesQueried == 7
                ? $"Captured {snapshot.CapturedAtUtc.ToLocalTime():MMM d · HH:mm:ss}. Fixed local channels only; event message bodies are not collected."
                : $"Captured {snapshot.CapturedAtUtc.ToLocalTime():MMM d · HH:mm:ss}. {snapshot.SourcesQueried} of 7 event sources were readable.";
            SourceWarnings.Text = snapshot.Warnings.Count == 0
                ? "Updates live every second while this page is open. Event observations are not yet correlated into incidents or response actions."
                : string.Join("  •  ", snapshot.Warnings);
            ApplyFilters();
        }
        finally
        {
            _requestInFlight = false;
        }
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilters();

    private void SeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e) => ApplyFilters();

    private void ApplyFilters()
    {
        if (EventList is null) return;
        var search = SearchBox.Text.Trim();
        var selectedSeverity = (SeverityFilter.SelectedItem as ComboBoxItem)?.Content?.ToString();
        var results = _observations
            .Where(item => string.IsNullOrWhiteSpace(selectedSeverity) || selectedSeverity == "All severity levels" || item.Severity.Equals(selectedSeverity, StringComparison.OrdinalIgnoreCase))
            .Where(item => string.IsNullOrWhiteSpace(search) ||
                item.Summary.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                item.LogName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                item.Provider.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                item.EventId.ToString().Contains(search, StringComparison.OrdinalIgnoreCase) ||
                item.Technique.Contains(search, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.CreatedAtUtc)
            .ToArray();

        CollectionReconciler.Apply(Events, results.Select(ToRow).ToArray(), row => row.Key,
            (current, incoming) => current.UpdateFrom(incoming));

        EventCount.Text = $"{Events.Count:N0} / {_observations.Count:N0} events";
        EmptyState.Visibility = Events.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }

    private static SecurityEventRow ToRow(SecurityEventObservation item)
    {
        var color = item.Severity switch
        {
            "CRITICAL" => Color.FromArgb(255, 255, 86, 121),
            "HIGH" => Color.FromArgb(255, 255, 167, 82),
            "MEDIUM" => Color.FromArgb(255, 255, 218, 119),
            "LOW" => Color.FromArgb(255, 86, 210, 235),
            _ => Color.FromArgb(255, 170, 183, 199)
        };
        var key = GetEventKey(item);
        return new SecurityEventRow(key,
            item.CreatedAtUtc?.ToLocalTime().ToString("MMM d HH:mm:ss") ?? "Time unavailable",
            item.Severity,
            new SolidColorBrush(color),
            item.Summary,
            $"{item.LogName} · {item.Provider} · record {item.RecordId?.ToString() ?? "unknown"}",
            $"{item.EventId} · {item.Technique}");
    }

    private static string GetEventKey(SecurityEventObservation item)
    {
        if (item.EventId == 4625 && item.Occurrences > 1)
        {
            // The provider emits one rolling five-minute aggregate. Its latest record and timestamp
            // change as failures arrive, but it remains the same summary row between refreshes.
            return $"{item.LogName}\0{item.Provider}\0{item.EventId.ToString(CultureInfo.InvariantCulture)}\0failed-logon-burst";
        }

        if (item.RecordId is { } recordId)
        {
            return $"{item.LogName}\0{recordId.ToString(CultureInfo.InvariantCulture)}";
        }

        // When Windows does not provide a record id, use the immutable observation fields.
        return string.Join('\0', item.LogName, item.Provider,
            item.EventId.ToString(CultureInfo.InvariantCulture),
            item.CreatedAtUtc?.UtcDateTime.Ticks.ToString(CultureInfo.InvariantCulture) ?? "time-unavailable",
            item.Severity, item.Technique, item.Summary);
    }
}

public sealed class SecurityEventRow : ObservableRow
{
    private string _time;
    private string _severity;
    private SolidColorBrush _severityBrush;
    private string _summary;
    private string _source;
    private string _technique;

    public SecurityEventRow(string key, string time, string severity, SolidColorBrush severityBrush,
        string summary, string source, string technique)
    {
        Key = key;
        _time = time;
        _severity = severity;
        _severityBrush = severityBrush;
        _summary = summary;
        _source = source;
        _technique = technique;
    }

    public string Key { get; }
    public string Time { get => _time; private set => SetProperty(ref _time, value); }
    public string Severity { get => _severity; private set => SetProperty(ref _severity, value); }
    public SolidColorBrush SeverityBrush { get => _severityBrush; private set => SetBrush(ref _severityBrush, value); }
    public string Summary { get => _summary; private set => SetProperty(ref _summary, value); }
    public string Source { get => _source; private set => SetProperty(ref _source, value); }
    public string Technique { get => _technique; private set => SetProperty(ref _technique, value); }

    public void UpdateFrom(SecurityEventRow incoming)
    {
        Time = incoming.Time;
        Severity = incoming.Severity;
        SeverityBrush = incoming.SeverityBrush;
        Summary = incoming.Summary;
        Source = incoming.Source;
        Technique = incoming.Technique;
    }

    private void SetBrush(ref SolidColorBrush current, SolidColorBrush incoming)
    {
        if (current.Color == incoming.Color) return;
        current = incoming;
        RaisePropertyChanged(nameof(SeverityBrush));
    }
}
