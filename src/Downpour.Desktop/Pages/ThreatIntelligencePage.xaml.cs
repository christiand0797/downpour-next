using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Downpour_Desktop.Pages;

public sealed class FeedEntryRow
{
    public required string Value { get; init; }
    public required string Type { get; init; }
    public required string Label { get; init; }
    public override string ToString() => $"{Value}, {Type}, {Label}";
}

/// <summary>Searchable view of the databases the local service has downloaded (replaces the old per-click abuse.ch API calls).</summary>
public sealed partial class ThreatIntelligencePage : Page
{
    private readonly ThreatDatabaseClient _client = new();
    private readonly DispatcherTimer _debounce = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private readonly DispatcherTimer _statusTimer = new() { Interval = TimeSpan.FromSeconds(5) };
    private CancellationTokenSource _lifetime = new();
    private IReadOnlyList<ThreatFeedStatus> _feeds = [];
    private int _query;

    public ThreatIntelligencePage()
    {
        InitializeComponent();
        _debounce.Tick += async (_, _) => { _debounce.Stop(); await BrowseAsync(); };
        _statusTimer.Tick += async (_, _) => await LoadFeedsAsync();
        Loaded += async (_, _) =>
        {
            if (_lifetime.IsCancellationRequested) { _lifetime.Dispose(); _lifetime = new(); }
            _statusTimer.Start();
            await LoadFeedsAsync();
        };
        Unloaded += (_, _) => { _statusTimer.Stop(); _debounce.Stop(); _lifetime.Cancel(); };
    }

    private async Task LoadFeedsAsync()
    {
        try
        {
            await App.EnsureSensorServiceAsync();
            var response = await _client.GetSnapshotAsync(_lifetime.Token);
            if (response?.Snapshot is not { } snapshot)
            {
                EmptyText.Text = _client.FailureMessage;
                return;
            }
            var browsable = snapshot.Feeds.Where(f => f.Kind != ThreatFeedKinds.Geo).ToArray();
            var changed = browsable.Length != _feeds.Count || browsable.Zip(_feeds).Any(p => p.First.Id != p.Second.Id || p.First.Entries != p.Second.Entries);
            _feeds = browsable;
            if (!changed && FeedPicker.Items.Count > 0) { ShowDetail(); return; }
            var selected = (FeedPicker.SelectedItem as ComboBoxItem)?.Tag as string ?? browsable.FirstOrDefault(f => f.Entries > 0)?.Id;
            FeedPicker.Items.Clear();
            foreach (var feed in browsable)
                FeedPicker.Items.Add(new ComboBoxItem { Content = feed.Entries > 0 ? $"{feed.Name}  ·  {feed.Entries:N0}" : $"{feed.Name}  ·  not loaded", Tag = feed.Id });
            FeedPicker.SelectedItem = FeedPicker.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (string)i.Tag == selected) ?? FeedPicker.Items.FirstOrDefault();
        }
        catch (OperationCanceledException) { }
    }

    private void ShowDetail()
    {
        if (CurrentFeed() is not { } feed) return;
        FeedDetail.Text = $"{feed.Provider} · {feed.License} · {feed.Purpose}" +
                          (feed.RetrievedAtUtc is { } at ? $" Updated {at.ToLocalTime():MMM d HH:mm}." : " Not downloaded yet.") +
                          (feed.Error is { } error ? $" Last problem: {error}" : "");
    }

    private ThreatFeedStatus? CurrentFeed() =>
        (FeedPicker.SelectedItem as ComboBoxItem)?.Tag is string id ? _feeds.FirstOrDefault(f => f.Id == id) : null;

    private async void FeedPicker_SelectionChanged(object sender, SelectionChangedEventArgs e) => await BrowseAsync();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _debounce.Stop();
        _debounce.Start();
    }

    private async Task BrowseAsync()
    {
        if (CurrentFeed() is not { } feed) return;
        ShowDetail();
        var query = ++_query;
        try
        {
            var response = await _client.BrowseAsync(feed.Id, SearchBox.Text, _lifetime.Token);
            if (query != _query) return; // a newer search superseded this one
            if (response?.Browse is not { } rows)
            {
                EmptyText.Text = _client.FailureMessage;
                EntryList.ItemsSource = null;
                return;
            }
            TotalText.Text = feed.Entries.ToString("N0");
            MatchingText.Text = response.BrowseTotal.ToString("N0");
            EntryList.ItemsSource = rows.Select(r => new FeedEntryRow { Value = r.Value, Type = r.Type.ToUpperInvariant(), Label = r.Label }).ToArray();
            EmptyText.Text = rows.Count > 0 ? "" : feed.Entries == 0
                ? "This database has not been downloaded yet. Use Update now on the Threat Databases page, or check Settings → Threat database updates."
                : "No entries match that search.";
            if (response.BrowseTotal > rows.Count) EmptyText.Text = "";
        }
        catch (OperationCanceledException) { }
    }

    private void OpenDatabases_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("threat-databases");
}
