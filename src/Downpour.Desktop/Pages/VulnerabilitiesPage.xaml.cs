using System.Collections.ObjectModel;
using Downpour.Core;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class VulnerabilitiesPage : Page
{
    private readonly InstalledSoftwareInventoryClient _softwareClient = new();
    private readonly KevCatalogClient _catalogClient = new();
    private readonly KevCatalogCache _catalogCache = new();
    private readonly SemaphoreSlim _matchGate = new(1, 1);
    private IReadOnlyList<Downpour.Contracts.InstalledSoftwareEntry> _software = [];
    private IReadOnlyList<KevEntry> _catalog = [];
    private IReadOnlyList<KevSoftwareCandidate> _candidates = [];
    private bool _initialized;
    private bool _softwareBusy;
    private bool _catalogBusy;
    private bool _candidateLimitReached;

    public ObservableCollection<InstalledSoftwareRow> VisibleSoftware { get; } = [];
    public ObservableCollection<KevCandidateRow> VisibleCandidates { get; } = [];

    public VulnerabilitiesPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (_initialized) return;
        _initialized = true;
        _ = LoadCacheAsync();
        _ = RefreshSoftwareAsync();
    }

    private async void RefreshInventory_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshSoftwareAsync();
    private async void RefreshCatalog_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshCatalogAsync();
    private void SearchBox_TextChanged(object sender, TextChangedEventArgs args) => ApplyFilter();

    private async Task LoadCacheAsync()
    {
        try
        {
            var cached = await Task.Run(() => _catalogCache.TryRead());
            if (cached is null)
            {
                CatalogStatus.Text = "No validated CISA catalog is cached. Select Refresh CISA catalog to download it.";
                return;
            }
            _catalog = cached.Snapshot.Entries;
            CatalogStatus.Text = $"CISA KEV {cached.Snapshot.CatalogVersion} · {_catalog.Count:N0} entries · cached {cached.Age:g} · {(cached.IsStale ? "stale" : "current")}.";
            await RebuildCandidatesAsync();
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or Newtonsoft.Json.JsonException)
        {
            CatalogStatus.Text = $"Validated CISA cache unavailable ({exception.GetType().Name}). Refresh the catalog to replace it.";
        }
    }

    private async Task RefreshSoftwareAsync()
    {
        if (_softwareBusy) return;
        _softwareBusy = true;
        RefreshInventoryButton.IsEnabled = false;
        InventoryStatus.Text = "Reading installed application display metadata from the local registry…";
        try
        {
            var snapshot = await _softwareClient.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _softwareClient.TryGetSnapshotAsync();
            }
            if (snapshot is null)
            {
                _software = [];
                InventoryStatus.Text = $"Installed software inventory is unavailable. {App.SensorServiceStatusHint}";
                await RebuildCandidatesAsync();
                return;
            }

            _software = snapshot.Software;
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var warningText = snapshot.Warnings.Count == 0 ? "" : $" · {string.Join(" ", snapshot.Warnings)}";
            InventoryStatus.Text = $"{snapshot.TotalCount:N0} uninstall-key entries · {snapshot.CollectionStatus.ToLowerInvariant()} · captured {captured:HH:mm:ss}{warningText}";
            await RebuildCandidatesAsync();
        }
        finally
        {
            _softwareBusy = false;
            RefreshInventoryButton.IsEnabled = true;
        }
    }

    private async Task RefreshCatalogAsync()
    {
        if (_catalogBusy) return;
        _catalogBusy = true;
        RefreshCatalogButton.IsEnabled = false;
        CatalogStatus.Text = _catalog.Count > 0 ? "Refreshing CISA catalog; current validated data remains visible…" : "Downloading CISA catalog…";
        try
        {
            var downloaded = await _catalogClient.FetchWithPayloadAsync();
            await Task.Run(() => _catalogCache.Write(downloaded));
            _catalog = downloaded.Snapshot.Entries;
            CatalogStatus.Text = $"CISA KEV {downloaded.Snapshot.CatalogVersion} · {_catalog.Count:N0} entries · retrieved {downloaded.Snapshot.RetrievedAtUtc.ToLocalTime():HH:mm:ss}.";
            await RebuildCandidatesAsync();
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidDataException or TaskCanceledException or UnauthorizedAccessException or Newtonsoft.Json.JsonException)
        {
            CatalogStatus.Text = $"CISA refresh failed ({exception.GetType().Name}); no fresh data is being claimed.";
        }
        finally
        {
            _catalogBusy = false;
            RefreshCatalogButton.IsEnabled = true;
        }
    }

    private async Task RebuildCandidatesAsync()
    {
        await _matchGate.WaitAsync();
        try
        {
            var software = _software;
            var catalog = _catalog;
            if (software.Count == 0 || catalog.Count == 0)
            {
                _candidates = [];
                _candidateLimitReached = false;
            }
            else
            {
                (_candidates, _candidateLimitReached) = await Task.Run(() =>
                {
                    var matches = KevSoftwareMatchEngine.FindCandidates(software, catalog, out var limited);
                    return (matches, limited);
                });
            }
            ApplyFilter();
        }
        finally
        {
            _matchGate.Release();
        }
    }

    private void ApplyFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        var software = _software.Where(entry => query.Length == 0 ||
            entry.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            entry.Version.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            entry.Publisher.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        VisibleSoftware.Clear();
        foreach (var row in software.Take(1000)) VisibleSoftware.Add(new InstalledSoftwareRow(row.Name, row.Version, row.Publisher, row.RegistryScope));
        SoftwareCount.Text = $"{VisibleSoftware.Count:N0} / {_software.Count:N0}";
        SoftwareEmpty.Text = _software.Count == 0 ? "No inventory rows are currently available." : software.Length == 0 ? "No software matches this filter." : "";
        SoftwareEmpty.Visibility = VisibleSoftware.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;

        var candidates = _candidates.Where(candidate => query.Length == 0 ||
            candidate.CveId.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            candidate.Vendor.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            candidate.Product.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            candidate.InstalledName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            candidate.InstalledPublisher.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        VisibleCandidates.Clear();
        foreach (var row in candidates.Take(KevSoftwareMatchEngine.MaximumCandidates)) VisibleCandidates.Add(new KevCandidateRow(row));
        CandidateCount.Text = _candidateLimitReached ? $"{VisibleCandidates.Count:N0}+ CANDIDATES" : $"{VisibleCandidates.Count:N0} CANDIDATES";
        CandidateEmpty.Text = _catalog.Count == 0 ? "Refresh the CISA catalog and software inventory to calculate candidates." :
            _software.Count == 0 ? "Installed software inventory is unavailable." : candidates.Length == 0 ? "No cautious vendor/product name candidates were found." : "";
        CandidateEmpty.Visibility = VisibleCandidates.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }
}

public sealed class InstalledSoftwareRow(string name, string version, string publisher, string scope)
{
    public string Name { get; set; } = name;
    public string Version { get; set; } = version;
    public string Publisher { get; set; } = publisher;
    public string Scope { get; set; } = scope;
    public string Detail => $"{(Version.Length == 0 ? "Version unknown" : Version)} · {(Publisher.Length == 0 ? "Publisher unknown" : Publisher)} · {Scope}";
}

public sealed class KevCandidateRow(KevSoftwareCandidate candidate)
{
    public KevSoftwareCandidate Candidate { get; set; } = candidate;
    public string Headline => $"{Candidate.CveId} · {Candidate.VulnerabilityName}";
    public string ProductLine => $"CISA product: {Candidate.Vendor} · {Candidate.Product} · added {Candidate.DateAdded:yyyy-MM-dd}";
    public string InstalledLine => $"Name candidate: {Candidate.InstalledName} {(Candidate.InstalledVersion.Length == 0 ? "· version unknown" : $"· version {Candidate.InstalledVersion}")}";
}
