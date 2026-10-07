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

public sealed partial class CleanupPage : Page
{
    private CleanupReport? _latestReport;
    private bool _scanInFlight;

    public ObservableCollection<CleanupCategoryRow> Categories { get; } = [];

    public CleanupPage()
    {
        InitializeComponent();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (_latestReport is null)
        {
            await ScanAsync();
        }
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        await ScanAsync();
    }

    private async Task ScanAsync()
    {
        if (_scanInFlight) return;
        _scanInFlight = true;
        ScanButton.IsEnabled = false;
        StatusHeadline.Text = "Scanning cleanup locations...";
        StatusDetail.Text = "Calculating temporary files, caches, and error logs across system drives...";

        try
        {
            var report = await CleanupInspector.ScanAsync();
            _latestReport = report;

            TotalSpaceText.Text = CleanupInspector.FormatBytes(report.TotalReclaimableBytes);
            TotalFilesText.Text = $"{report.TotalReclaimableFiles:N0}";
            StatusHeadline.Text = $"Scan complete: {CleanupInspector.FormatBytes(report.TotalReclaimableBytes)} reclaimable space identified";
            StatusDetail.Text = $"Found {report.TotalReclaimableFiles:N0} candidate items across {report.Categories.Count} categories. Strictly read-only preview mode.";

            Categories.Clear();
            foreach (var cat in report.Categories.OrderByDescending(c => c.TotalBytes))
            {
                Categories.Add(new CleanupCategoryRow(cat));
            }

            EmptyCategoriesState.Visibility = Categories.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Scan encountered an error";
            StatusDetail.Text = ex.Message;
        }
        finally
        {
            _scanInFlight = false;
            ScanButton.IsEnabled = true;
        }
    }

    private void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        if (_latestReport is null)
        {
            StatusDetail.Text = "Run a scan before exporting a report.";
            return;
        }

        try
        {
            var reportText = CleanupInspector.GenerateTextReport(_latestReport);
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var exportDir = Directory.Exists(desktopPath) ? desktopPath : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Downpour", "Reports");
            Directory.CreateDirectory(exportDir);

            var fileName = $"downpour_cleanup_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            var fullPath = Path.Combine(exportDir, fileName);
            File.WriteAllText(fullPath, reportText, Encoding.UTF8);

            StatusHeadline.Text = "Cleanup Report Exported";
            StatusDetail.Text = $"Exported space preview report to: {fullPath}";
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Export Failed";
            StatusDetail.Text = ex.Message;
        }
    }
}

public sealed class CleanupCategoryRow : ObservableRow
{
    public string Label { get; }
    public string Description { get; }
    public string FormattedSize { get; }
    public string FormattedFiles { get; }
    public string RiskLevel { get; }
    public SolidColorBrush RiskBackground { get; }
    public SolidColorBrush RiskForeground { get; }
    public string OldestItemDate { get; }
    public string LargestItemNote { get; }

    public CleanupCategoryRow(CleanupCategory category)
    {
        Label = category.Label;
        Description = category.Description;
        FormattedSize = CleanupInspector.FormatBytes(category.TotalBytes);
        FormattedFiles = $"{category.FileCount:N0} files";
        RiskLevel = category.RiskLevel;

        Color riskCol = category.RiskLevel switch
        {
            "Moderate" => Color.FromArgb(255, 240, 136, 62),
            "Warning" => Color.FromArgb(255, 248, 81, 73),
            _ => Color.FromArgb(255, 63, 185, 80)
        };

        RiskForeground = new SolidColorBrush(riskCol);
        RiskBackground = new SolidColorBrush(Color.FromArgb(40, riskCol.R, riskCol.G, riskCol.B));

        OldestItemDate = string.IsNullOrEmpty(category.OldestItemDate) ? "—" : $"Oldest: {category.OldestItemDate}";
        LargestItemNote = category.LargestItemBytes.HasValue
            ? $"Max: {CleanupInspector.FormatBytes(category.LargestItemBytes.Value)}"
            : "";
    }
}
