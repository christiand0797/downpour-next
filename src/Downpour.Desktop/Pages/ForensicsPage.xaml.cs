using System.Collections.ObjectModel;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class ForensicsPage : Page
{
    private ForensicEvidenceBundle? _latestBundle;
    private bool _collectionInFlight;

    public ObservableCollection<ForensicArtifactRow> ArtifactRows { get; } = [];

    public ForensicsPage()
    {
        InitializeComponent();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (_latestBundle is null)
        {
            await CollectAsync();
        }
    }

    private async void Collect_Click(object sender, RoutedEventArgs e)
    {
        await CollectAsync();
    }

    private async Task CollectAsync()
    {
        if (_collectionInFlight) return;
        _collectionInFlight = true;
        CollectButton.IsEnabled = false;
        StatusHeadline.Text = "Collecting forensic evidence...";
        StatusDetail.Text = "Gathering chain of custody, security alerts, event logs, persistence items, and network indicators...";

        try
        {
            await App.EnsureSensorServiceAsync();
            var bundle = await ForensicEvidenceCollector.CollectAsync();
            _latestBundle = bundle;

            var coc = bundle.ChainOfCustody;
            int critHighCount = bundle.Artifacts.Count(a =>
                a.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) ||
                a.Severity.Equals("HIGH", StringComparison.OrdinalIgnoreCase));

            TotalEvidenceText.Text = $"{bundle.TotalEvidenceCount:N0}";
            CriticalHighText.Text = $"{critHighCount:N0}";
            AttackerIpsText.Text = $"{bundle.AttackerIps.Count:N0}";

            StatusHeadline.Text = $"Forensic collection complete: {bundle.TotalEvidenceCount} items captured";
            StatusDetail.Text = $"Evidence cryptographically signed with SHA-256 seal. {bundle.AttackerIps.Count} external indicators, {bundle.SuspiciousPersistenceItems.Count} persistence flags.";

            // Update Chain of Custody card
            ChainOfCustodyCard.Visibility = Visibility.Visible;
            CocHostnameText.Text = coc.Hostname;
            CocOsText.Text = $"{coc.OsDescription} ({coc.OsArchitecture})";
            CocIpText.Text = coc.LocalIpAddresses;
            CocMacText.Text = coc.MacAddresses;
            CocSha256Text.Text = coc.EvidenceIntegritySha256;

            ArtifactRows.Clear();
            foreach (var art in bundle.Artifacts)
            {
                ArtifactRows.Add(new ForensicArtifactRow(art));
            }

            EmptyState.Visibility = ArtifactRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            ApplyFilter();
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Evidence collection encountered an error";
            StatusDetail.Text = ex.Message;
        }
        finally
        {
            _collectionInFlight = false;
            CollectButton.IsEnabled = true;
        }
    }

    private void ExportHtml_Click(object sender, RoutedEventArgs e)
    {
        if (_latestBundle is null)
        {
            StatusDetail.Text = "Collect evidence before exporting a report.";
            return;
        }

        try
        {
            var html = ForensicEvidenceCollector.GenerateHtmlReport(_latestBundle);
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var exportDir = Directory.Exists(desktopPath)
                ? desktopPath
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Downpour", "Reports");
            Directory.CreateDirectory(exportDir);

            var fileName = $"downpour_forensic_report_{DateTime.Now:yyyyMMdd_HHmmss}.html";
            var fullPath = Path.Combine(exportDir, fileName);
            File.WriteAllText(fullPath, html, Encoding.UTF8);

            StatusHeadline.Text = "Legal Incident Report Exported";
            StatusDetail.Text = $"Exported executive HTML evidence report to: {fullPath}";
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "HTML Export Failed";
            StatusDetail.Text = ex.Message;
        }
    }

    private void ExportJson_Click(object sender, RoutedEventArgs e)
    {
        if (_latestBundle is null)
        {
            StatusDetail.Text = "Collect evidence before exporting an evidence bundle.";
            return;
        }

        try
        {
            var json = ForensicEvidenceCollector.GenerateJsonBundle(_latestBundle);
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var exportDir = Directory.Exists(desktopPath)
                ? desktopPath
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Downpour", "Reports");
            Directory.CreateDirectory(exportDir);

            var fileName = $"downpour_forensic_bundle_{DateTime.Now:yyyyMMdd_HHmmss}.json";
            var fullPath = Path.Combine(exportDir, fileName);
            File.WriteAllText(fullPath, json, Encoding.UTF8);

            StatusHeadline.Text = "Raw Evidence Bundle Exported";
            StatusDetail.Text = $"Exported machine-readable JSON evidence bundle to: {fullPath}";
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "JSON Export Failed";
            StatusDetail.Text = ex.Message;
        }
    }

    private void OpenIc3_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _ = Windows.System.Launcher.LaunchUriAsync(new Uri("https://www.ic3.gov"));
        }
        catch
        {
            // Fallback
        }
    }

    private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        ApplyFilter();
    }

    private void Filter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        var selectedCat = (CategoryFilter?.SelectedItem as string) ?? "All Categories";
        var selectedSev = (SeverityFilter?.SelectedItem as string) ?? "All Severities";

        foreach (var row in ArtifactRows)
        {
            bool matchQuery = query.Length == 0 ||
                row.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Detail.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.Category.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                row.TechniqueDisplay.Contains(query, StringComparison.OrdinalIgnoreCase);

            bool matchCat = selectedCat.Equals("All Categories", StringComparison.OrdinalIgnoreCase) ||
                row.Category.Equals(selectedCat, StringComparison.OrdinalIgnoreCase);

            bool matchSev = selectedSev.Equals("All Severities", StringComparison.OrdinalIgnoreCase) ||
                row.Severity.Equals(selectedSev, StringComparison.OrdinalIgnoreCase);

            row.Visibility = (matchQuery && matchCat && matchSev) ? Visibility.Visible : Visibility.Collapsed;
        }
    }
}

public sealed class ForensicArtifactRow : ObservableRow
{
    private Visibility _visibility = Visibility.Visible;

    public ForensicArtifactItem Artifact { get; }
    public string Severity => Artifact.Severity;
    public string Category => Artifact.Category;
    public string Title => Artifact.Title;
    public string Detail => Artifact.Detail;
    public string TechniqueDisplay => string.IsNullOrWhiteSpace(Artifact.Technique) ? "" : $"ATT&CK {Artifact.Technique}";
    public string RawReferenceDisplay => string.IsNullOrWhiteSpace(Artifact.RawEvidenceReference) ? "" : $"Ref: {Artifact.RawEvidenceReference}";
    public string TimestampDisplay => Artifact.TimestampUtc.HasValue ? Artifact.TimestampUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "—";

    public SolidColorBrush SeverityForeground { get; }
    public SolidColorBrush SeverityBackground { get; }

    public Visibility Visibility
    {
        get => _visibility;
        set => SetProperty(ref _visibility, value);
    }

    public ForensicArtifactRow(ForensicArtifactItem artifact)
    {
        Artifact = artifact;

        Color sevColor = artifact.Severity.ToUpperInvariant() switch
        {
            "CRITICAL" => Color.FromArgb(255, 248, 81, 73),
            "HIGH" => Color.FromArgb(255, 255, 123, 114),
            "MEDIUM" => Color.FromArgb(255, 210, 153, 34),
            "LOW" => Color.FromArgb(255, 63, 185, 80),
            _ => Color.FromArgb(255, 88, 166, 255)
        };

        SeverityForeground = new SolidColorBrush(sevColor);
        SeverityBackground = new SolidColorBrush(Color.FromArgb(36, sevColor.R, sevColor.G, sevColor.B));
    }
}
