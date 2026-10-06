using System.Collections.ObjectModel;
using System.Linq;
using Downpour.Core;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class ThreatIntelligencePage : Page
{
    private readonly UrlhausClient _urlhausClient = new();
    private readonly AbuseChClient _abuseChClient = new();
    private UrlhausPayload? _urlhausPayload;
    private MalwareBazaarPayload? _malwareBazaarPayload;
    private FeodoTrackerPayload? _feodoPayload;
    private SslBlacklistPayload? _sslBlacklistPayload;
    private bool _urlhausLoading;
    private bool _abuseChLoading;

    public ObservableCollection<UrlhausEntryRow> VisibleUrlhausUrls { get; } = [];
    public ObservableCollection<MalwareBazaarRow> VisibleMalwareBazaar { get; } = [];
    public ObservableCollection<FeodoTrackerRow> VisibleFeodo { get; } = [];
    public ObservableCollection<SslBlacklistRow> VisibleSslBlacklist { get; } = [];

    public ThreatIntelligencePage() => InitializeComponent();

    private async void FetchUrlhausRecent_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (_urlhausLoading) return;
        _urlhausLoading = true;
        RefreshUrlhausButton.IsEnabled = false;
        RefreshUrlhausButton.Content = "Fetching...";
        StatusText.Text = "Fetching recent URLs from URLhaus...";
        try
        {
            _urlhausPayload = await _urlhausClient.FetchRecentUrlsAsync(1000);
            ApplyUrlhausFilter();
            StatusText.Text = _urlhausPayload?.Urls.Count > 0
                ? $"Loaded {_urlhausPayload.Urls.Count:N0} URLs from URLhaus."
                : "No URLs returned from URLhaus.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"URLhaus fetch failed: {ex.Message}";
        }
        finally
        {
            _urlhausLoading = false;
            RefreshUrlhausButton.IsEnabled = true;
            RefreshUrlhausButton.Content = "Fetch URLhaus recent";
        }
    }

    private async void FetchAbuseChFeeds_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (_abuseChLoading) return;
        _abuseChLoading = true;
        RefreshAbuseChButton.IsEnabled = false;
        RefreshAbuseChButton.Content = "Fetching...";
        StatusText.Text = "Fetching feeds from Abuse.ch (Malware Bazaar, Feodo Tracker, SSL Blacklist)...";
        try
        {
            var task1 = _abuseChClient.FetchRecentSamplesAsync(1000);
            var task2 = _abuseChClient.FetchFeodoIpBlocklistAsync();
            var task3 = _abuseChClient.FetchSslBlacklistAsync();
            await Task.WhenAll(task1, task2, task3);
            _malwareBazaarPayload = task1.Result;
            _feodoPayload = task2.Result;
            _sslBlacklistPayload = task3.Result;

            ApplyMalwareBazaarFilter();
            ApplyFeodoFilter();
            ApplySslBlacklistFilter();

            var total = (_malwareBazaarPayload?.Samples.Count ?? 0) +
                        (_feodoPayload?.Entries.Count ?? 0) +
                        (_sslBlacklistPayload?.Entries.Count ?? 0);
            StatusText.Text = total > 0
                ? $"Loaded {total:N0} entries from Abuse.ch feeds."
                : "No data returned from Abuse.ch feeds.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Abuse.ch fetch failed: {ex.Message}";
        }
        finally
        {
            _abuseChLoading = false;
            RefreshAbuseChButton.IsEnabled = true;
            RefreshAbuseChButton.Content = "Fetch Abuse.ch feeds";
        }
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyAllFilters();

    private void ApplyAllFilters()
    {
        ApplyUrlhausFilter();
        ApplyMalwareBazaarFilter();
        ApplyFeodoFilter();
        ApplySslBlacklistFilter();
    }

    private void ApplyUrlhausFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        VisibleUrlhausUrls.Clear();
        if (_urlhausPayload?.Urls is { } urls)
        {
            var filtered = urls.Where(u => query.Length == 0 ||
                u.Url.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                u.Threat.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                u.Tags.Any(t => t.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
                u.Id.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var row in filtered) VisibleUrlhausUrls.Add(new UrlhausEntryRow(row));
        }
        UrlhausCount.Text = VisibleUrlhausUrls.Count > 0 ? $"{VisibleUrlhausUrls.Count:N0} urls" : "0 urls";
        UrlhausEmpty.Visibility = VisibleUrlhausUrls.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }

    private void ApplyMalwareBazaarFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        VisibleMalwareBazaar.Clear();
        if (_malwareBazaarPayload?.Samples is { } samples)
        {
            var filtered = samples.Where(s => query.Length == 0 ||
                s.FileName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                s.Signature.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                s.Tags.Any(t => t.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
                s.Sha256.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                s.Reporter.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var row in filtered) VisibleMalwareBazaar.Add(new MalwareBazaarRow(row));
        }
        MalwareBazaarCount.Text = VisibleMalwareBazaar.Count > 0 ? $"{VisibleMalwareBazaar.Count:N0} samples" : "0 samples";
        MalwareBazaarEmpty.Visibility = VisibleMalwareBazaar.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }

    private void ApplyFeodoFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        VisibleFeodo.Clear();
        if (_feodoPayload?.Entries is { } entries)
        {
            var filtered = entries.Where(e => query.Length == 0 ||
                e.Ip.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                e.Malware.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                e.Country.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                e.C2Status.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var row in filtered) VisibleFeodo.Add(new FeodoTrackerRow(row));
        }
        FeodoCount.Text = VisibleFeodo.Count > 0 ? $"{VisibleFeodo.Count:N0} C2 IPs" : "0 C2 IPs";
        FeodoEmpty.Visibility = VisibleFeodo.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }

    private void ApplySslBlacklistFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        VisibleSslBlacklist.Clear();
        if (_sslBlacklistPayload?.Entries is { } entries)
        {
            var filtered = entries.Where(e => query.Length == 0 ||
                e.Ja3.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                e.Reason.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                e.Sha1.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var row in filtered) VisibleSslBlacklist.Add(new SslBlacklistRow(row));
        }
        SslBlacklistCount.Text = VisibleSslBlacklist.Count > 0 ? $"{VisibleSslBlacklist.Count:N0} JA3s" : "0 JA3s";
        SslBlacklistEmpty.Visibility = VisibleSslBlacklist.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }
}

public sealed class UrlhausEntryRow(UrlhausEntry entry)
{
    public UrlhausEntry Entry { get; } = entry;
    public string Url => Entry.Url;
    public string Threat => Entry.Threat;
    public string TagsDisplay => Entry.Tags.Count > 0 ? string.Join(", ", Entry.Tags) : "no tags";
    public string DateAddedDisplay => Entry.DateAdded != DateTimeOffset.MinValue
        ? $"Added: {Entry.DateAdded:yyyy-MM-dd HH:mm:ss UTC}"
        : "Date unknown";
}

public sealed class MalwareBazaarRow(MalwareBazaarSample sample)
{
    public MalwareBazaarSample Sample { get; } = sample;
    public string FileName => Sample.FileName.Length > 0 ? Sample.FileName : "(no filename)";
    public string Signature => Sample.Signature.Length > 0 ? Sample.Signature : "(unknown family)";
    public string TagsDisplay => Sample.Tags.Count > 0 ? string.Join(", ", Sample.Tags) : "no tags";
    public string HashesDisplay => $"SHA256: {Prefix(Sample.Sha256)} SHA1: {Prefix(Sample.Sha1)} MD5: {Prefix(Sample.Md5)}";

    private static string Prefix(string? hash) => string.IsNullOrEmpty(hash) ? "(none)" : hash.Length > 16 ? $"{hash[..16]}..." : hash;
}

public sealed class FeodoTrackerRow(FeodoTrackerEntry entry)
{
    public FeodoTrackerEntry Entry { get; } = entry;
    public string IpPort => Entry.Port.HasValue ? $"{Entry.Ip}:{Entry.Port} ({Entry.Protocol})" : $"{Entry.Ip} ({Entry.Protocol})";
    public string Malware => Entry.Malware.Length > 0 ? Entry.Malware : "(unknown)";
    public string LocationDisplay => $"{Entry.Country} • {Entry.Isp} • ASN: {Entry.Asn}";
    public string StatusDisplay => $"C2: {Entry.C2Status} • First: {Entry.FirstSeen:yyyy-MM-dd} • Last: {Entry.LastSeen:yyyy-MM-dd}";
}

public sealed class SslBlacklistRow(SslBlacklistEntry entry)
{
    public SslBlacklistEntry Entry { get; } = entry;
    public string Ja3Display => Entry.Ja3.Length > 64 ? $"{Entry.Ja3[..64]}..." : Entry.Ja3;
    public string Reason => Entry.Reason.Length > 0 ? Entry.Reason : "(no reason)";
    public string DateDisplay => Entry.FirstSeen != DateTimeOffset.MinValue
        ? $"First: {Entry.FirstSeen:yyyy-MM-dd} • Last: {Entry.LastSeen:yyyy-MM-dd}"
        : "Dates unknown";
}