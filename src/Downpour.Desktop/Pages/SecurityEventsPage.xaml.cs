using System.Collections.ObjectModel;
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

    public SecurityEventsPage()
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
            StatusHeadline.Text = $"Event source connected · {snapshot.Events.Count:N0} observations in the 24-hour lookback";
            StatusDetail.Text = snapshot.SourcesQueried == 7
                ? $"Captured {snapshot.CapturedAtUtc.ToLocalTime():MMM d · HH:mm:ss}. Fixed local channels only; event message bodies are not collected."
                : $"Captured {snapshot.CapturedAtUtc.ToLocalTime():MMM d · HH:mm:ss}. {snapshot.SourcesQueried} of 7 event sources were readable.";
            SourceWarnings.Text = snapshot.Warnings.Count == 0
                ? "Refreshes every 15 seconds while this page is open. Event observations are not yet correlated into incidents or response actions."
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

        Events.Clear();
        foreach (var item in results)
        {
            var color = item.Severity switch
            {
                "CRITICAL" => Color.FromArgb(255, 255, 86, 121),
                "HIGH" => Color.FromArgb(255, 255, 167, 82),
                "MEDIUM" => Color.FromArgb(255, 255, 218, 119),
                "LOW" => Color.FromArgb(255, 86, 210, 235),
                _ => Color.FromArgb(255, 170, 183, 199)
            };
            Events.Add(new SecurityEventRow(
                item.CreatedAtUtc?.ToLocalTime().ToString("MMM d HH:mm:ss") ?? "Time unavailable",
                item.Severity,
                new SolidColorBrush(color),
                item.Summary,
                $"{item.LogName} · {item.Provider} · record {item.RecordId?.ToString() ?? "unknown"}",
                $"{item.EventId} · {item.Technique}"));
        }

        EventCount.Text = $"{Events.Count:N0} / {_observations.Count:N0} events";
        EmptyState.Visibility = Events.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }
}

public sealed class SecurityEventRow(string time, string severity, SolidColorBrush severityBrush, string summary, string source, string technique)
{
    public string Time { get; } = time;
    public string Severity { get; } = severity;
    public SolidColorBrush SeverityBrush { get; } = severityBrush;
    public string Summary { get; } = summary;
    public string Source { get; } = source;
    public string Technique { get; } = technique;
}
