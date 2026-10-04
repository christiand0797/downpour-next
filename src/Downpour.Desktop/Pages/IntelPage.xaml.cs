using System.Collections.ObjectModel;
using Downpour.Core;
using Newtonsoft.Json;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class IntelPage : Page
{
    private readonly KevCatalogClient _client = new();
    private readonly KevCatalogCache _cache = new();
    private IReadOnlyList<KevEntry> _entries = [];
    private bool _requestInFlight;
    private bool _initialized;

    public ObservableCollection<KevEntryRow> VisibleEntries { get; } = [];

    public IntelPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (!_initialized)
        {
            _initialized = true;
            LoadCache();
            _ = RefreshAsync();
        }
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        RefreshButton.IsEnabled = false;
        SourceState.Text = _entries.Count > 0 ? "REFRESHING · CURRENT CATALOG REMAINS VISIBLE" : "FETCHING CISA CATALOG…";
        SourceDetails.Text = "Connecting to the fixed CISA HTTPS endpoint. The request is time and size bounded.";
        try
        {
            var download = await _client.FetchWithPayloadAsync();
            var catalog = download.Snapshot;
            _cacheRetrievedAt = catalog.RetrievedAtUtc;
            _entries = catalog.Entries;
            var cacheSaved = true;
            try { _cache.Write(download); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
            {
                cacheSaved = false;
            }
            SourceState.Text = cacheSaved ? "CISA HTTPS · FRESH · CACHE UPDATED" : "CISA HTTPS · FRESH · CACHE NOT SAVED";
            SourceDetails.Text = $"Catalog {catalog.CatalogVersion} · released {catalog.ReleasedOn:yyyy-MM-dd} · downloaded {catalog.RetrievedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} · {_entries.Count:N0} validated records.";
            ApplyFilter();
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidDataException or JsonReaderException or JsonSerializationException or TaskCanceledException)
        {
            SourceState.Text = _entries.Count > 0 ? "SOURCE UNAVAILABLE · SHOWING VALIDATED CACHE" : "SOURCE UNAVAILABLE · NO CURRENT DATA";
            SourceDetails.Text = _entries.Count > 0
                ? $"CISA refresh failed ({exception.Message}). Showing the locally validated catalog, retrieved {_cacheRetrievedAt?.ToLocalTime():yyyy-MM-dd HH:mm:ss}; cached data is limited to {KevCatalogCache.MaximumAge.TotalDays:0} days."
                : exception is TaskCanceledException
                    ? "CISA request timed out. Retry when the source is reachable. No recent validated cache is available."
                    : $"CISA catalog could not be safely loaded ({exception.Message}). No recent validated cache is available.";
            ApplyFilter();
        }
        finally
        {
            RefreshButton.IsEnabled = true;
            _requestInFlight = false;
        }
    }

    private DateTimeOffset? _cacheRetrievedAt;

    private void LoadCache()
    {
        try
        {
            var cached = _cache.TryRead();
            if (cached is null)
            {
                SourceState.Text = File.Exists(_cache.CachePath) ? "LOCAL CACHE EXPIRED" : "NOT LOADED";
                SourceDetails.Text = File.Exists(_cache.CachePath)
                    ? "The saved catalog is older than the seven-day offline limit. Refresh to retrieve current data."
                    : "No saved catalog is available yet. Refresh to retrieve CISA KEV.";
                return;
            }

            _entries = cached.Snapshot.Entries;
            _cacheRetrievedAt = cached.Snapshot.RetrievedAtUtc;
            SourceState.Text = cached.IsStale ? "CISA KEV · STALE CACHE" : "CISA KEV · VALIDATED CACHE";
            SourceDetails.Text = $"Catalog {cached.Snapshot.CatalogVersion} · released {cached.Snapshot.ReleasedOn:yyyy-MM-dd} · retrieved {_cacheRetrievedAt.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss} · cached {FormatAge(cached.Age)} · {_entries.Count:N0} validated records. Refresh checks CISA for updates.";
            ApplyFilter();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException or FormatException or JsonReaderException or JsonSerializationException)
        {
            SourceState.Text = "LOCAL CACHE REJECTED";
            SourceDetails.Text = $"The saved catalog failed its integrity or schema check ({exception.Message}). Refresh to replace it with current CISA data.";
        }
    }

    private static string FormatAge(TimeSpan age) => age.TotalHours < 1
        ? $"{Math.Max(0, (int)age.TotalMinutes)} min ago"
        : age.TotalDays < 1 ? $"{(int)age.TotalHours} hr ago" : $"{(int)age.TotalDays} days ago";

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void ApplyFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        var matched = _entries.Where(entry => query.Length == 0 ||
            entry.CveId.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            entry.Vendor.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            entry.Product.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            entry.VulnerabilityName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            entry.Description.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        VisibleEntries.Clear();
        foreach (var entry in matched.Take(500))
            VisibleEntries.Add(new KevEntryRow(entry.CveId, entry.Vendor, entry.Product, entry.VulnerabilityName, entry.DateAdded.ToString("yyyy-MM-dd"), entry.Description));
        ResultCount.Text = _entries.Count == 0 ? "" : $"{matched.Length:N0} MATCHES · SHOWING {VisibleEntries.Count:N0}";
        EmptyState.Text = _entries.Count == 0 ? "Refresh the catalog to load CISA KEV entries." : matched.Length == 0 ? "No entries match this search." : "";
        EmptyState.Visibility = VisibleEntries.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }
}

public sealed class KevEntryRow(string cveId, string vendor, string product, string vulnerabilityName, string dateAdded, string description)
{
    public string CveId { get; set; } = cveId;
    public string Vendor { get; set; } = vendor;
    public string Product { get; set; } = product;
    public string VulnerabilityName { get; set; } = vulnerabilityName;
    public string DateAdded { get; set; } = dateAdded;
    public string Description { get; set; } = description;
    public string ProductLine => $"{Vendor} · {Product}";
}
