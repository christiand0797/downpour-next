using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

/// <summary>
/// v29's CVE dashboard: the CISA KEV catalog related to this PC. Windows flaws added after the newest installed update
/// are flagged as likely missing, installed apps are matched by product name, and each entry opens CISA's required
/// action, deadline, EPSS exploit probability and the NVD and Microsoft advisories. Read-only.
/// </summary>
public sealed partial class CvePage : Page
{
    private readonly KevCatalogClient _catalogClient = new();
    private readonly KevCatalogCache _catalogCache = new();
    private readonly InstalledSoftwareInventoryClient _softwareClient = new();
    private readonly HardeningPostureClient _postureClient = new();
    private readonly EpssClient _epss = new();
    private IReadOnlyList<KevEntry> _catalog = [];
    private IReadOnlyList<CveAssessment> _assessed = [];
    private DateTimeOffset? _lastUpdate;
    private bool _loaded;
    private bool _busy;

    private readonly TrendChart _monthChart = new() { Title = "Newly exploited per month", Subtitle = "CVEs CISA added to the catalog, last 24 months" };
    private readonly TopBarsChart _vendorChart = new() { Title = "Most exploited vendors", Subtitle = "Catalog entries per vendor" };
    private readonly BreakdownChart _exposureChart = new() { Title = "This PC", Subtitle = "How the catalog relates to this computer" };

    public CvePage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _monthChart, _vendorChart, _exposureChart);
        YearFilter.Items.Add(new ComboBoxItem { Content = "All years" });
        for (var year = DateTime.UtcNow.Year; year >= DateTime.UtcNow.Year - 3; year--) YearFilter.Items.Add(new ComboBoxItem { Content = year.ToString() });
        YearFilter.Items.Add(new ComboBoxItem { Content = "Older" });
        YearFilter.SelectedIndex = 0;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (_loaded) return;
        _loaded = true;
        _ = LoadAsync(refresh: false);
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync(refresh: true);

    private void Hardening_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("hardening");

    private async void WindowsUpdate_Click(object sender, RoutedEventArgs e) => await InstallUpdatesAsync();

    private async Task InstallUpdatesAsync()
    {
        InstallUpdatesButton.IsEnabled = false;
        try
        {
            var result = await UpdateRunner.RunAsync(XamlRoot, "software", text => WindowsDetail.Text = text);
            if (result is not null) await LoadAsync(refresh: false);
            if (result is not null) WindowsDetail.Text = FixerClient.Describe(result);
        }
        finally { InstallUpdatesButton.IsEnabled = true; }
    }

    private async Task LoadAsync(bool refresh)
    {
        if (_busy) return;
        _busy = true;
        RefreshButton.IsEnabled = false;
        try
        {
            var postureTask = _postureClient.TryGetSnapshotAsync();
            var softwareTask = _softwareClient.TryGetSnapshotAsync();
            await LoadCatalogAsync(refresh);
            var posture = await postureTask;
            var software = await softwareTask;
            _lastUpdate = posture?.LastUpdateUtc;
            var candidates = software is null || _catalog.Count == 0 ? [] : await Task.Run(() => KevSoftwareMatchEngine.FindCandidates(software.Software, _catalog, out _));
            _assessed = await Task.Run(() => CveExposure.Assess(_catalog, _lastUpdate, candidates));
            Summarise(posture, software is not null);
            ApplyFilter();
        }
        finally
        {
            _busy = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private async Task LoadCatalogAsync(bool refresh)
    {
        try
        {
            var cached = refresh ? null : await Task.Run(() => _catalogCache.TryRead());
            if (cached is not null && !cached.IsStale)
            {
                _catalog = cached.Snapshot.Entries;
                CatalogStatus.Text = $"CISA Known Exploited Vulnerabilities {cached.Snapshot.CatalogVersion} · {_catalog.Count:N0} flaws confirmed exploited in the wild · checked {cached.Age.TotalHours:0} h ago.";
                return;
            }
            CatalogStatus.Text = "Downloading the CISA Known Exploited Vulnerabilities catalog…";
            var downloaded = await _catalogClient.FetchWithPayloadAsync();
            await Task.Run(() => _catalogCache.Write(downloaded));
            _catalog = downloaded.Snapshot.Entries;
            CatalogStatus.Text = $"CISA Known Exploited Vulnerabilities {downloaded.Snapshot.CatalogVersion} · {_catalog.Count:N0} flaws confirmed exploited in the wild · downloaded just now.";
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or TaskCanceledException or UnauthorizedAccessException or Newtonsoft.Json.JsonException)
        {
            if (_catalog.Count == 0)
            {
                try { if (await Task.Run(() => _catalogCache.TryRead()) is { } stale) _catalog = stale.Snapshot.Entries; }
                catch (Exception inner) when (inner is IOException or InvalidDataException or UnauthorizedAccessException) { }
            }
            CatalogStatus.Text = _catalog.Count > 0
                ? $"Could not refresh the CISA catalog ({ex.GetType().Name}); showing the saved copy of {_catalog.Count:N0} entries."
                : $"Could not download the CISA catalog ({ex.GetType().Name}). Check the internet connection and select Refresh catalog.";
        }
    }

    private void Summarise(HardeningPostureSnapshot? posture, bool softwareRead)
    {
        var missing = _assessed.Where(a => a.LikelyMissingOnThisPc).ToArray();
        var installed = _assessed.Count(a => a.InstalledMatches.Count > 0);
        var ransomware = _assessed.Count(a => a.Entry.RansomwareUse);
        var windows = _assessed.Count(a => a.IsWindows);

        if (_lastUpdate is { } last)
        {
            var days = (int)(DateTimeOffset.UtcNow - last).TotalDays;
            WindowsHeadline.Text = missing.Length == 0 ? "Up to date" : $"{missing.Length} likely missing";
            WindowsHeadline.Foreground = Brush(missing.Length == 0 ? Color.FromArgb(255, 120, 230, 160) : Color.FromArgb(255, 255, 120, 110));
            WindowsDetail.Text = (missing.Length == 0
                ? $"No actively exploited Windows flaw was published after your newest update ({last:yyyy-MM-dd}, {days} days ago)."
                : $"Actively exploited Windows flaws were published after your newest update ({last:yyyy-MM-dd}, {days} days ago). Install updates to close them.")
                + (posture?.OsBuild is { } build ? $" Build {build}." : "");
        }
        else
        {
            WindowsHeadline.Text = "Unknown";
            WindowsDetail.Text = posture is null ? $"The update history is unavailable. {App.SensorServiceStatusHint}" : "Windows did not report when updates were last installed.";
        }

        AppsHeadline.Text = softwareRead ? $"{installed} to review" : "Unavailable";
        AppsDetail.Text = softwareRead
            ? "Catalog entries naming software installed on this PC. A name match does not prove your version is affected; check the vendor advisory."
            : $"Installed software could not be read. {App.SensorServiceStatusHint}";
        RansomwareHeadline.Text = $"{ransomware:N0}";
        RansomwareDetail.Text = $"Catalog flaws ransomware gangs are known to use, of {_catalog.Count:N0} in total ({windows:N0} in Windows itself).";

        var since = DateOnly.FromDateTime(DateTime.UtcNow.AddMonths(-23));
        var first = new DateOnly(since.Year, since.Month, 1);
        _monthChart.SetSeries(Enumerable.Range(0, 24).Select(i => first.AddMonths(i)).Select(month =>
            (new DateTimeOffset(month.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero),
             (double)_catalog.Count(e => e.DateAdded.Year == month.Year && e.DateAdded.Month == month.Month))));
        _vendorChart.SetData(_catalog.GroupBy(e => e.Vendor, StringComparer.OrdinalIgnoreCase).Select(g => (g.Key, (double)g.Count())).OrderByDescending(x => x.Item2).Take(8));
        _exposureChart.SetData(
        [
            ("Likely missing", missing.Length),
            ("Installed app match", _assessed.Count(a => a.InstalledMatches.Count > 0 && !a.LikelyMissingOnThisPc)),
            ("Other Windows flaws", _assessed.Count(a => a.IsWindows && !a.LikelyMissingOnThisPc)),
        ], new Dictionary<string, Color> { ["Likely missing"] = HudPalette.Critical });
    }

    private void Filter_Changed(object sender, object e) => ApplyFilter();

    private void ApplyFilter()
    {
        if (CveList is null || ScopeFilter is null || YearFilter is null) return;
        var query = SearchBox.Text.Trim();
        var scope = ScopeFilter.SelectedIndex;
        var yearText = (YearFilter.SelectedItem as ComboBoxItem)?.Content as string;
        var rows = _assessed.Where(a => scope switch
            {
                1 => a.LikelyMissingOnThisPc,
                2 => a.InstalledMatches.Count > 0,
                3 => a.IsWindows,
                4 => a.Entry.Vendor.Equals("Microsoft", StringComparison.OrdinalIgnoreCase),
                5 => a.Entry.RansomwareUse,
                _ => true,
            })
            .Where(a => yearText is null or "All years" || (yearText == "Older"
                ? a.Entry.DateAdded.Year < DateTime.UtcNow.Year - 3
                : a.Entry.DateAdded.Year.ToString() == yearText))
            .Where(a => query.Length == 0 || a.Entry.CveId.Contains(query, StringComparison.OrdinalIgnoreCase)
                || a.Entry.Vendor.Contains(query, StringComparison.OrdinalIgnoreCase) || a.Entry.Product.Contains(query, StringComparison.OrdinalIgnoreCase)
                || a.Entry.VulnerabilityName.Contains(query, StringComparison.OrdinalIgnoreCase) || a.Entry.Description.Contains(query, StringComparison.OrdinalIgnoreCase))
            .Select(a => new CveRow(a)).ToArray();
        CveList.ItemsSource = rows;
        ResultCount.Text = $"{rows.Length:N0} of {_assessed.Count:N0}";
    }

    private async void CveList_ItemClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is CveRow row && XamlRoot is { } root) await ShowDetailsAsync(root, row.Assessment);
    }

    private async Task ShowDetailsAsync(XamlRoot root, CveAssessment a)
    {
        var entry = a.Entry;
        var body = new StackPanel { Spacing = 8, MaxWidth = 720 };
        void Line(string label, string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            body.Children.Add(new TextBlock { Text = label.ToUpperInvariant(), FontSize = 10, CharacterSpacing = 60, Foreground = (Brush)Application.Current.Resources["HudCyanBrush"] });
            body.Children.Add(new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        }
        Line("This PC", a.LikelyMissingOnThisPc
            ? $"Likely missing: published to the catalog on {entry.DateAdded:yyyy-MM-dd}, after the newest update on this PC ({_lastUpdate:yyyy-MM-dd}). Run Windows Update."
            : a.InstalledMatches.Count > 0 ? $"Name match with installed software: {string.Join(", ", a.InstalledMatches)}. Check whether your version is affected."
            : a.IsWindows ? "Windows flaw; fixed by updates installed after it was published." : "No match with this PC.");
        Line("What it is", entry.Description);
        Line("Affected", $"{entry.Vendor} {entry.Product}");
        Line("What to do (CISA)", entry.RequiredAction);
        Line("Dates", $"Added to the catalog {entry.DateAdded:yyyy-MM-dd}" + (entry.DueDate is { } due ? $" · US federal fix deadline {due:yyyy-MM-dd}" : ""));
        Line("Ransomware", entry.RansomwareUse ? "Known to be used in ransomware campaigns." : "");
        Line("Notes", entry.Notes);
        var epssText = new TextBlock { Text = "Exploit probability (EPSS) not checked.", TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"] };
        body.Children.Add(epssText);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        Button Add(string text, Func<Task> run)
        {
            var b = new Button { Content = text };
            b.Click += async (_, _) => await run();
            buttons.Children.Add(b);
            return b;
        }
        Add("Open NVD", () => Open(CveExposure.NvdUrl(entry.CveId)));
        if (CveExposure.MicrosoftUrl(entry) is { } msrc) Add("Microsoft advisory", () => Open(msrc));
        if (a.IsWindows) Add("Install updates now", InstallUpdatesAsync);
        Button? epssButton = null;
        epssButton = Add("Check EPSS", async () =>
        {
            epssButton!.IsEnabled = false;
            epssText.Text = "Asking FIRST.org for this CVE's exploit probability (only the CVE ID is sent)…";
            try
            {
                var score = await _epss.FetchAsync(entry.CveId);
                epssText.Text = score is null
                    ? "FIRST.org has no EPSS score for this CVE."
                    : $"EPSS {score.Score:P1} chance of exploitation in the next 30 days · higher than {score.Percentile:P0} of all CVEs · scored {score.ScoreDate:yyyy-MM-dd}.";
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException or IOException)
            {
                epssText.Text = $"EPSS lookup failed ({ex.GetType().Name}).";
                epssButton.IsEnabled = true;
            }
        });
        Add("Copy", () =>
        {
            EntityDetails.Copy($"{entry.CveId} · {entry.VulnerabilityName}\n{entry.Vendor} {entry.Product}\n{entry.Description}\nRequired action: {entry.RequiredAction}\nAdded {entry.DateAdded:yyyy-MM-dd}{(entry.DueDate is { } d ? $", due {d:yyyy-MM-dd}" : "")}\n{CveExposure.NvdUrl(entry.CveId)}");
            return Task.CompletedTask;
        });
        body.Children.Add(buttons);

        var dialog = new ContentDialog
        {
            Title = $"{entry.CveId} · {entry.VulnerabilityName}",
            Content = new ScrollViewer { Content = body, MaxHeight = 560 },
            CloseButtonText = "Close",
            XamlRoot = root,
        };
        dialog.Resources["ContentDialogMaxWidth"] = 820.0;
        await dialog.ShowAsync();
    }

    /// <summary>Opens only NVD, Microsoft Security Response Center and the Windows Update settings page.</summary>
    private static async Task Open(string uri)
    {
        if (!(uri.StartsWith("https://nvd.nist.gov/vuln/detail/CVE-", StringComparison.Ordinal)
              || uri.StartsWith("https://msrc.microsoft.com/update-guide/vulnerability/CVE-", StringComparison.Ordinal)
              || uri == "ms-settings:windowsupdate")) return;
        try { await Windows.System.Launcher.LaunchUriAsync(new Uri(uri)); }
        catch (Exception ex) when (ex is UriFormatException or InvalidOperationException or System.Runtime.InteropServices.COMException) { }
    }

    private static SolidColorBrush Brush(Color color) => new(color);
}

public sealed class CveRow(CveAssessment assessment)
{
    public CveAssessment Assessment => assessment;
    public string CveId => assessment.Entry.CveId;
    public string Name => assessment.Entry.VulnerabilityName;
    public string Product => $"{assessment.Entry.Vendor} · {assessment.Entry.Product}";
    public string Added => $"added {assessment.Entry.DateAdded:yyyy-MM-dd}";
    public string Extra => assessment.Entry.DueDate is { } due ? $"fix by {due:yyyy-MM-dd}" : "";

    public string Badge => assessment.LikelyMissingOnThisPc ? "LIKELY MISSING"
        : assessment.InstalledMatches.Count > 0 ? "INSTALLED APP"
        : assessment.Entry.RansomwareUse ? "RANSOMWARE"
        : assessment.IsWindows ? "WINDOWS" : "EXPLOITED";

    public SolidColorBrush BadgeForeground => new(Badge switch
    {
        "LIKELY MISSING" => Color.FromArgb(255, 255, 120, 110),
        "INSTALLED APP" => Color.FromArgb(255, 255, 181, 86),
        "RANSOMWARE" => Color.FromArgb(255, 244, 21, 204),
        "WINDOWS" => Color.FromArgb(255, 60, 145, 255),
        _ => Color.FromArgb(255, 201, 192, 157),
    });

    public SolidColorBrush BadgeBackground => new(Color.FromArgb(40, BadgeForeground.Color.R, BadgeForeground.Color.G, BadgeForeground.Color.B));
}
