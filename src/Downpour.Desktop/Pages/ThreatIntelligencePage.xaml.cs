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
    private CancellationTokenSource? _browseCancellation;
    private int _query;
    private int _pageOffset;
    private int? _nextOffset;
    private bool _browsing;
    private bool _loadingFeeds;
    private bool _ready;

    public ThreatIntelligencePage()
    {
        InitializeComponent();
        _ready = true;
        EntityDetails.Attach(EntryList, item => item is FeedEntryRow r ? DetailDescriptions.FeedEntry(r.Value, r.Type, r.Label) : null);
        _debounce.Tick += async (_, _) => { _debounce.Stop(); await BrowseAsync(); };
        _statusTimer.Tick += async (_, _) => await LoadFeedsAsync();
        Loaded += async (_, _) =>
        {
            if (_lifetime.IsCancellationRequested) { _lifetime.Dispose(); _lifetime = new(); }
            _statusTimer.Start();
            await LoadFeedsAsync();
        };
        Unloaded += (_, _) => { _statusTimer.Stop(); _debounce.Stop(); _lifetime.Cancel(); CancelBrowse(); };
    }

    private async Task LoadFeedsAsync()
    {
        if (_loadingFeeds || _lifetime.IsCancellationRequested) return;
        _loadingFeeds = true;
        var token = _lifetime.Token;
        try
        {
            await App.EnsureSensorServiceAsync();
            var response = await _client.GetSnapshotAsync(token);
            if (token.IsCancellationRequested) return;
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
        finally { _loadingFeeds = false; }
    }

    private void ShowDetail()
    {
        if (CurrentFeed() is not { } feed) return;
        FeedDetail.Text = $"{feed.Provider} · {feed.License} · {feed.Purpose}" +
                          (feed.RetrievedAtUtc is { } at ? $" Downloaded {at.ToLocalTime():yyyy-MM-dd HH:mm}." : " Not downloaded yet.") +
                          (feed.SourcePublishedAtUtc is { } published ? $" Source published {published.ToUniversalTime():yyyy-MM-dd HH:mm} UTC." : " Source publication date unknown.") +
                          $" {feed.FreshnessNote ?? "Download time does not establish when these indicators were last seen."}" +
                          (feed.Error is { } error ? $" Last problem: {error}" : "");
    }

    private ThreatFeedStatus? CurrentFeed() =>
        (FeedPicker.SelectedItem as ComboBoxItem)?.Tag is string id ? _feeds.FirstOrDefault(f => f.Id == id) : null;

    private async void FeedPicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready) return;
        _debounce.Stop();
        await BrowseAsync();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready) return;
        CancelBrowse();
        _pageOffset = 0;
        _nextOffset = null;
        UpdatePaging();
        _debounce.Stop();
        _debounce.Start();
    }

    private async void Previous_Click(object sender, RoutedEventArgs e) => await BrowseAsync(Math.Max(0, _pageOffset - ThreatFeedBrowser.PageSize));
    private async void Next_Click(object sender, RoutedEventArgs e)
    {
        if (_nextOffset is { } next) await BrowseAsync(next);
    }

    private void CancelBrowse()
    {
        _query++;
        _browseCancellation?.Cancel();
        _browseCancellation?.Dispose();
        _browseCancellation = null;
        _browsing = false;
    }

    private void UpdatePaging()
    {
        PreviousButton.IsEnabled = !_browsing && _pageOffset > 0;
        NextButton.IsEnabled = !_browsing && _nextOffset is not null;
    }

    private async Task BrowseAsync(int offset = 0)
    {
        CancelBrowse();
        if (CurrentFeed() is not { } feed || _lifetime.IsCancellationRequested) return;
        ShowDetail();
        var query = _query;
        _browseCancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        var token = _browseCancellation.Token;
        _browsing = true;
        UpdatePaging();
        PageStatusText.Text = "Searching the complete local database…";
        try
        {
            var response = await _client.BrowseAsync(feed.Id, SearchBox.Text, token, offset);
            if (query != _query || token.IsCancellationRequested) return; // a newer search superseded this one
            if (response is not { Accepted: true, Browse: { } rows })
            {
                EmptyText.Text = response is null ? _client.FailureMessage : $"Search could not complete: {response.ResultCode}.";
                PageStatusText.Text = "Search unavailable";
                _pageOffset = 0;
                _nextOffset = null;
                EntryList.ItemsSource = null;
                return;
            }
            _pageOffset = response.BrowseOffset;
            _nextOffset = response.BrowseNextOffset;
            TotalText.Text = feed.Entries.ToString("N0");
            MatchingText.Text = response.BrowseTotal.ToString("N0");
            PageStatusText.Text = rows.Count == 0 ? "No matching entries" :
                $"Showing {_pageOffset + 1:N0}–{_pageOffset + rows.Count:N0} of {response.BrowseTotal:N0} · local search";
            EntryList.ItemsSource = rows.Select(r => new FeedEntryRow { Value = r.Value, Type = r.Type.ToUpperInvariant(), Label = r.Label }).ToArray();
            EmptyText.Text = rows.Count > 0 ? "" : feed.Entries == 0
                ? "This database has not been downloaded yet. Use Update now on the Threat Databases page, or check Settings → Threat database updates."
                : "No entries match that search.";
            if (response.BrowseTotal > rows.Count) EmptyText.Text = "";
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (query == _query)
            {
                _browsing = false;
                UpdatePaging();
            }
        }
    }

    private void OpenDatabases_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("threat-databases");
}
