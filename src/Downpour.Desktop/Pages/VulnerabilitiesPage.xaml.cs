using System.Collections.ObjectModel;
using System.Text;
using Downpour.Core;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class VulnerabilitiesPage : Page
{
    private readonly InstalledSoftwareInventoryClient _softwareClient = new();
    private readonly KevCatalogClient _catalogClient = new();
    private readonly KevCatalogCache _catalogCache = new();
    private readonly NvdClient _nvdClient = new();
    private readonly SemaphoreSlim _matchGate = new(1, 1);
    private readonly SemaphoreSlim _nvdGate = new(1, 1);
    private IReadOnlyList<Downpour.Contracts.InstalledSoftwareEntry> _software = [];
    private IReadOnlyList<KevEntry> _catalog = [];
    private IReadOnlyList<KevSoftwareCandidate> _candidates = [];
    private bool _initialized;
    private bool _softwareBusy;
    private bool _catalogBusy;
    private bool _nvdBusy;
    private bool _candidateLimitReached;

    public ObservableCollection<InstalledSoftwareRow> VisibleSoftware { get; } = [];
    public ObservableCollection<KevCandidateRow> VisibleCandidates { get; } = [];

    public VulnerabilitiesPage()
    {
        InitializeComponent();
        EntityDetails.Attach(SoftwareList, item => item is InstalledSoftwareRow s ? DetailDescriptions.Software(s.Name, s.Version, s.Publisher, s.Scope) : null);
        EntityDetails.Attach(CandidateList, item => item is KevCandidateRow k ? DetailDescriptions.Kev(k.Candidate) : null);
    }

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

    private async void EnrichNvd_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (_nvdBusy || _candidates.Count == 0) return;
        _nvdBusy = true;
        EnrichNvdButton.IsEnabled = false;
        EnrichNvdButton.Content = "Enriching with NVD…";
        try
        {
            NvdStatus.Text = "Fetching NVD CVE data for candidates…";
            var findings = await VulnerabilityMatchEngine.FindVulnerabilitiesAsync(_software, _catalog, _nvdClient);

            // Build a lookup of enriched findings by CVE ID
            var findingLookup = findings.ToDictionary(f => f.CveId, f => f, StringComparer.OrdinalIgnoreCase);

            // Update candidates with NVD enrichment
            var enrichedCandidates = new List<KevSoftwareCandidate>();
            foreach (var candidate in _candidates)
            {
                var enriched = candidate;
                if (findingLookup.TryGetValue(candidate.CveId, out var finding))
                {
                    // Merge affected products from NVD
                    var affectedProducts = finding.AffectedProducts
                        .Where(ap => ap.CpeVendor.Equals(candidate.Vendor, StringComparison.OrdinalIgnoreCase)
                            && ap.CpeProduct.Equals(candidate.Product, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (affectedProducts.Count > 0)
                    {
                        var ap = affectedProducts[0];
                        enriched = candidate with
                        {
                            InstalledName = ap.InstalledName,
                            InstalledVersion = ap.InstalledVersion,
                            InstalledPublisher = ap.InstalledPublisher,
                        };
                    }
                }
                enrichedCandidates.Add(enriched);
            }

            _candidates = enrichedCandidates;
            ApplyFilter();
            NvdStatus.Text = $"NVD enrichment complete: {findings.Count} CVE(s) with NVD data, {_candidates.Count(c => findingLookup.ContainsKey(c.CveId))} candidates enriched.";
        }
        catch (Exception exception)
        {
            NvdStatus.Text = $"NVD enrichment failed: {exception.Message}";
        }
        finally
        {
            _nvdBusy = false;
            EnrichNvdButton.IsEnabled = _candidates.Count > 0;
            EnrichNvdButton.Content = "Enrich with NVD";
        }
    }

    private async void CheckNvdForCandidate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is not Button { DataContext: KevCandidateRow row }) return;
        if (row.Candidate is null) return;

        var cveId = row.Candidate.CveId;
        if (string.IsNullOrWhiteSpace(cveId)) return;

        var button = (Button)sender;
        button.IsEnabled = false;
        button.Content = "Checking…";

        try
        {
            await _nvdGate.WaitAsync();
            try
            {
                var nvdData = await _nvdClient.FetchCveAsync(cveId);
                if (nvdData?.Entries.Count > 0)
                {
                    var nvdEntry = nvdData.Entries[0];

                    // Update the candidate with NVD data
                    var candidate = row.Candidate;
                    var affectedProducts = VulnerabilityMatchEngine.MatchAffectedProducts(
                        new KevEntry(candidate.CveId, candidate.Vendor, candidate.Product, candidate.VulnerabilityName, candidate.DateAdded, ""),
                        nvdEntry.CpeMatches,
                        _software.Select(entry => new InventoryItem(entry, Normalize(entry.Name), NormalizeVersion(entry.Version), Normalize(entry.Publisher)))
                            .Where(item => item.Name.Length > 0).ToArray(),
                        true);

                    if (affectedProducts.Count > 0)
                    {
                        var ap = affectedProducts[0];
                        row._versionAnalysis = ap.VersionAnalysis;
                        row._hasNvdData = true;
                        row.CvssV31Score = nvdEntry.CvssV31Score;
                        row.CvssV20Score = nvdEntry.CvssV20Score;
                        row.CvssV31Vector = nvdEntry.CvssV31Vector;
                        row.CvssV20Vector = nvdEntry.CvssV20Vector;
                        row._hasNvdData = true;
                    }
                    else
                    {
                        row._versionAnalysis = "No affected version match found in NVD CPE data for this product.";
                        row._hasNvdData = true;
                    }
                }
                else
                {
                    row._versionAnalysis = "No NVD data found for this CVE.";
                    row._hasNvdData = true;
                }

                ApplyFilter(); // Refresh UI to show updated data
            }
            finally
            {
                _nvdGate.Release();
            }
        }
        catch (Exception exception)
        {
            row._versionAnalysis = $"NVD lookup failed: {exception.Message}";
            row._hasNvdData = true;
            ApplyFilter();
        }
        finally
        {
            // Update button state
            if (sender is Button btn)
            {
                btn.IsEnabled = true;
                btn.Content = "Check NVD";
            }
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

    private string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var builder = new StringBuilder(Math.Min(value.Length, 512));
        var needsSpace = false;
        foreach (var character in value.Trim())
        {
            if (char.IsLetterOrDigit(character))
            {
                if (needsSpace && builder.Length > 0) builder.Append(' ');
                builder.Append(char.ToLowerInvariant(character));
                needsSpace = false;
            }
            else
            {
                needsSpace = true;
            }
            if (builder.Length >= 512) break;
        }
        return builder.ToString();
    }

    private string NormalizeVersion(string version)
    {
        if (string.IsNullOrWhiteSpace(version)) return "";
        var normalized = new string(version.Trim().Where(c => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_').ToArray());
        return normalized.Length <= 128 ? normalized : normalized[..128];
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

    // NVD enrichment fields
    public bool _hasNvdData;
    public bool HasNvdData => _hasNvdData;
    public string NvdLine => _hasNvdData ? "NVD data loaded" : "";
    public string _versionAnalysis = "";
    public string VersionAnalysis => _versionAnalysis;
    public double? CvssV31Score { get; set; }
    public double? CvssV20Score { get; set; }
    public string? CvssV31Vector { get; set; }
    public string? CvssV20Vector { get; set; }
    public string CvssScore => CvssV31Score is { } v31 ? $"v3.1: {v31:0.0}" : CvssV20Score is { } v20 ? $"v2.0: {v20:0.0}" : "—";
}
