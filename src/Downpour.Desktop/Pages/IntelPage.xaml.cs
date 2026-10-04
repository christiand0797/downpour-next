using System.Collections.ObjectModel;
using Downpour.Core;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class IntelPage : Page
{
    private readonly KevCatalogClient _client = new();
    private IReadOnlyList<KevEntry> _entries = [];
    private bool _requestInFlight;

    public ObservableCollection<KevEntryRow> VisibleEntries { get; } = [];

    public IntelPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (_entries.Count == 0) _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        RefreshButton.IsEnabled = false;
        SourceState.Text = "FETCHING CISA CATALOG…";
        SourceDetails.Text = "Connecting to the fixed CISA HTTPS endpoint. The request is time and size bounded.";
        try
        {
            var catalog = await _client.FetchAsync();
            _entries = catalog.Entries;
            SourceState.Text = "CISA HTTPS · FRESH";
            SourceDetails.Text = $"Catalog {catalog.CatalogVersion} · released {catalog.ReleasedOn:yyyy-MM-dd} · downloaded {catalog.RetrievedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} · {_entries.Count:N0} validated records.";
            ApplyFilter();
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidDataException or System.Text.Json.JsonException or TaskCanceledException)
        {
            SourceState.Text = "SOURCE UNAVAILABLE · NO CURRENT DATA";
            SourceDetails.Text = exception is TaskCanceledException
                ? "CISA request timed out. Retry when the source is reachable. No feed data is cached in this prototype."
                : $"CISA catalog could not be safely loaded ({exception.Message}). No feed data is cached in this prototype.";
            _entries = [];
            ApplyFilter();
        }
        finally
        {
            RefreshButton.IsEnabled = true;
            _requestInFlight = false;
        }
    }

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
