using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class DnsPage : Page, INotifyPropertyChanged
{
    private readonly DnsInventoryClient _client = new();
    private readonly List<DnsCacheEntry> _allEntries = [];
    private bool _requestInFlight;

    public LiveCollection<DnsFindingRow> Findings { get; } = [];
    public LiveCollection<DnsEntryRow> FilteredEntries { get; } = [];

    // Email auth state
    private string _spfStatus = "";
    private string _spfVerdict = "";
    private string _spfRecord = "";
    private string _dmarcStatus = "";
    private string _dmarcVerdict = "";
    private string _dmarcRecord = "";
    private string _dkimStatus = "";
    private string _dkimVerdict = "";
    private string _dkimSelector = "";

    public string SpfStatus { get => _spfStatus; set => SetField(ref _spfStatus, value); }
    public string SpfVerdict { get => _spfVerdict; set => SetField(ref _spfVerdict, value); }
    public string SpfRecord { get => _spfRecord; set => SetField(ref _spfRecord, value); }
    public string DmarcStatus { get => _dmarcStatus; set => SetField(ref _dmarcStatus, value); }
    public string DmarcVerdict { get => _dmarcVerdict; set => SetField(ref _dmarcVerdict, value); }
    public string DmarcRecord { get => _dmarcRecord; set => SetField(ref _dmarcRecord, value); }
    public string DkimStatus { get => _dkimStatus; set => SetField(ref _dkimStatus, value); }
    public string DkimVerdict { get => _dkimVerdict; set => SetField(ref _dkimVerdict, value); }
    public string DkimSelector { get => _dkimSelector; set => SetField(ref _dkimSelector, value); }

    public SolidColorBrush SpfForeground => GetStatusBrush(SpfStatus, true);
    public SolidColorBrush SpfBackground => GetStatusBrush(SpfStatus, false);
    public SolidColorBrush DmarcForeground => GetStatusBrush(DmarcStatus, true);
    public SolidColorBrush DmarcBackground => GetStatusBrush(DmarcStatus, false);
    public SolidColorBrush DkimForeground => GetStatusBrush(DkimStatus, true);
    public SolidColorBrush DkimBackground => GetStatusBrush(DkimStatus, false);

    public event PropertyChangedEventHandler? PropertyChanged;

    private readonly BreakdownChart _riskChart = new() { Title = "Cached domain risk", Subtitle = "Every name in the Windows DNS cache, scored" };
    private readonly TopBarsChart _typeChart = new() { Title = "Record types", Subtitle = "What kind of lookups are cached" };
    private readonly TopBarsChart _domainChart = new() { Title = "Busiest domains", Subtitle = "Cached names per registered domain" };

    private static string RecordTypeName(int type) => type switch
    {
        1 => "A (IPv4)", 2 => "NS", 5 => "CNAME (alias)", 6 => "SOA", 12 => "PTR (reverse)", 15 => "MX (mail)", 16 => "TXT",
        28 => "AAAA (IPv6)", 33 => "SRV", 64 => "SVCB", 65 => "HTTPS", _ => $"Type {type}",
    };

    /// <summary>Last two labels ("cdn.example.com" → "example.com"); good enough to group a cache view.</summary>
    private static string RegisteredDomain(string domain)
    {
        var labels = domain.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
        return labels.Length <= 2 ? domain : string.Join('.', labels[^2..]);
    }

    public DnsPage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _riskChart, _typeChart, _domainChart);
        LiveRefresh.Attach(this, () => RefreshAsync(quiet: true));
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void ApplyFilter()
    {
        var filter = SearchBox.Text?.Trim().ToLowerInvariant() ?? "";
        FilteredEntries.Clear();

        var query = string.IsNullOrEmpty(filter)
            ? _allEntries
            : _allEntries.Where(entry => entry.Domain.Contains(filter, StringComparison.OrdinalIgnoreCase));

        foreach (var entry in query.OrderByDescending(x => x.RiskScore))
            FilteredEntries.Add(new DnsEntryRow(entry));

        EmptyCacheState.Visibility = FilteredEntries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async Task RefreshAsync(bool quiet = false)
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        if (!quiet) RefreshButton.IsEnabled = false;
        if (!quiet) StatusHeadline.Text = "Checking DNS resolver cache";

        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            Findings.Clear();
            _allEntries.Clear();

            if (snapshot is null)
            {
                StatusHeadline.Text = "Downpour is running · DNS sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached DNS resolver table is shown.";
                EmptyFindingsState.Visibility = Visibility.Visible;
                EmptyCacheState.Visibility = Visibility.Visible;
                return;
            }

            App.MarkSensorServiceConnected();

            foreach (var finding in snapshot.Findings.OrderBy(f => SeverityRank(f.Severity)))
                Findings.Add(new DnsFindingRow(finding));

            _allEntries.AddRange(snapshot.Entries);
            ApplyFilter();

            EmptyFindingsState.Visibility = Findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            _riskChart.SetData(
            [
                ("High risk", snapshot.HighRiskCount),
                ("Medium risk", snapshot.MediumRiskCount),
                ("Low risk", Math.Max(0, snapshot.TotalEntries - snapshot.HighRiskCount - snapshot.MediumRiskCount)),
            ], new Dictionary<string, Windows.UI.Color> { ["High risk"] = HudPalette.Critical, ["Medium risk"] = HudPalette.Warning, ["Low risk"] = HudPalette.Good });
            _typeChart.SetData(snapshot.Entries.GroupBy(e => RecordTypeName(e.RecordType)).Select(g => (g.Key, (double)g.Count())), "", HudPalette.Categorical[1]);
            _domainChart.SetData(snapshot.Entries.GroupBy(e => RegisteredDomain(e.Domain), StringComparer.OrdinalIgnoreCase).Select(g => (g.Key, (double)g.Count())), "", HudPalette.Categorical[3]);
            var findingCount = snapshot.Findings.Count;
            var totalCount = snapshot.TotalEntries;
            var highCount = snapshot.HighRiskCount;
            var medCount = snapshot.MediumRiskCount;

            StatusHeadline.Text = findingCount == 0
                ? $"{totalCount} DNS cache entries · {highCount} high risk · {medCount} medium risk"
                : $"{totalCount} DNS cache entries · {findingCount} active finding{(findingCount == 1 ? "" : "s")}";

            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"Checked {captured:HH:mm:ss}. TOFU baseline active.{warnings}";
        }
        finally
        {
            _requestInFlight = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private async void VerifyDomain_Click(object sender, RoutedEventArgs e)
    {
        var domain = DomainInput.Text?.Trim();
        if (string.IsNullOrWhiteSpace(domain)) return;

        VerifyDomainButton.IsEnabled = false;
        try
        {
            var result = await Task.Run(() => EmailSecurityAnalyzer.Analyze(domain));
            SpfStatus = result.SpfStatus;
            SpfVerdict = result.SpfVerdict;
            SpfRecord = string.IsNullOrWhiteSpace(result.SpfRecord) ? "(No record)" : result.SpfRecord;

            DmarcStatus = result.DmarcStatus;
            DmarcVerdict = result.DmarcVerdict;
            DmarcRecord = string.IsNullOrWhiteSpace(result.DmarcRecord) ? "(No record)" : result.DmarcRecord;

            DkimStatus = result.DkimStatus;
            DkimVerdict = result.DkimVerdict;
            DkimSelector = string.IsNullOrWhiteSpace(result.DkimSelector) ? "(None found)" : result.DkimSelector;

            OnPropertyChanged(nameof(SpfForeground));
            OnPropertyChanged(nameof(SpfBackground));
            OnPropertyChanged(nameof(DmarcForeground));
            OnPropertyChanged(nameof(DmarcBackground));
            OnPropertyChanged(nameof(DkimForeground));
            OnPropertyChanged(nameof(DkimBackground));

            EmailAuthResultsPanel.Visibility = Visibility.Visible;
        }
        finally
        {
            VerifyDomainButton.IsEnabled = true;
        }
    }

    private static SolidColorBrush GetStatusBrush(string status, bool isForeground) => status switch
    {
        "OK" => new(isForeground ? Color.FromArgb(255, 120, 230, 160) : Color.FromArgb(48, 60, 200, 120)),
        "WARN" => new(isForeground ? Color.FromArgb(255, 255, 170, 90) : Color.FromArgb(48, 230, 150, 50)),
        "HIGH" => new(isForeground ? Color.FromArgb(255, 255, 120, 110) : Color.FromArgb(56, 240, 90, 70)),
        _ => new(isForeground ? Color.FromArgb(255, 180, 200, 220) : Color.FromArgb(40, 100, 140, 180))
    };

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4
    };

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        field = value;
        OnPropertyChanged(propertyName);
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public sealed class DnsFindingRow(DnsFinding finding)
{
    public string Severity => finding.Severity;
    public string Technique => finding.Technique;
    public string Summary => finding.Summary;
    public string Indicator => finding.Indicator;

    public SolidColorBrush SeverityForeground => new(finding.Severity switch
    {
        "CRITICAL" => Color.FromArgb(255, 255, 80, 80),
        "HIGH" => Color.FromArgb(255, 255, 120, 110),
        "MEDIUM" => Color.FromArgb(255, 255, 170, 90),
        _ => Color.FromArgb(255, 120, 230, 160)
    });

    public SolidColorBrush SeverityBackground => new(finding.Severity switch
    {
        "CRITICAL" => Color.FromArgb(56, 255, 60, 60),
        "HIGH" => Color.FromArgb(56, 240, 90, 70),
        "MEDIUM" => Color.FromArgb(48, 230, 150, 50),
        _ => Color.FromArgb(48, 60, 200, 120)
    });
}

public sealed class DnsEntryRow(DnsCacheEntry entry)
{
    public string Domain => entry.Domain;
    public string ScoreDisplay => $"{entry.RiskScore}";
    public string FactorsDisplay => string.Join(" · ", entry.Factors);
    public string RecordTypeDisplay => entry.RecordType switch
    {
        1 => "A (IPv4)",
        28 => "AAAA (IPv6)",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        _ => $"Type {entry.RecordType}"
    };

    public SolidColorBrush ScoreForeground => new(entry.RiskScore switch
    {
        >= 85 => Color.FromArgb(255, 255, 80, 80),
        >= 70 => Color.FromArgb(255, 255, 170, 90),
        >= 40 => Color.FromArgb(255, 255, 214, 102),
        _ => Color.FromArgb(255, 120, 230, 160)
    });

    public SolidColorBrush ScoreBackground => new(entry.RiskScore switch
    {
        >= 85 => Color.FromArgb(56, 255, 60, 60),
        >= 70 => Color.FromArgb(48, 230, 150, 50),
        >= 40 => Color.FromArgb(36, 230, 190, 60),
        _ => Color.FromArgb(36, 60, 200, 120)
    });
}
