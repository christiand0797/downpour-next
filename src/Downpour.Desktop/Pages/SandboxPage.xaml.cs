using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class SandboxPage : Page
{
    private SandboxReport? _latestReport;
    private bool _analysisInFlight;

    public ObservableCollection<SandboxIndicatorRow> IndicatorRows { get; } = [];

    public SandboxPage()
    {
        InitializeComponent();
    }

    private async void Browse_Click(object sender, RoutedEventArgs e)
    {
        StorageFile? file;
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".exe");
            picker.FileTypeFilter.Add(".dll");
            picker.FileTypeFilter.Add(".sys");
            picker.FileTypeFilter.Add(".bin");
            picker.FileTypeFilter.Add(".ps1");
            picker.FileTypeFilter.Add(".bat");
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            file = await picker.PickSingleFileAsync();
        }
        catch (Exception ex) when (ex is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            StatusDetail.Text = $"File picker could not be opened: {ex.Message}";
            return;
        }

        if (file is null) return;

        FilePathBox.Text = file.Path;
        await RunAnalysisAsync(file.Path);
    }

    private async void AnalyzeStatic_Click(object sender, RoutedEventArgs e)
    {
        var path = FilePathBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            StatusDetail.Text = "Please select or enter a sample file path to analyze.";
            return;
        }

        if (!File.Exists(path))
        {
            StatusDetail.Text = $"Target sample does not exist: {path}";
            return;
        }

        await RunAnalysisAsync(path);
    }

    private async Task RunAnalysisAsync(string filePath)
    {
        if (_analysisInFlight) return;
        _analysisInFlight = true;
        BrowseButton.IsEnabled = false;
        AnalyzeButton.IsEnabled = false;
        StatusHeadline.Text = "Analyzing Sample...";
        StatusDetail.Text = $"Reading '{Path.GetFileName(filePath)}', computing Shannon entropy, extracting PE headers, and scanning indicators...";

        try
        {
            var report = await Task.Run(() =>
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
                return SafeFileSandbox.AnalyzeStatic(stream, filePath);
            });

            _latestReport = report;

            // Update Metrics Cards
            VerdictText.Text = report.Verdict;
            VerdictText.Foreground = report.Verdict switch
            {
                "MALICIOUS" => new SolidColorBrush(Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
                "SUSPICIOUS" => new SolidColorBrush(Color.FromArgb(0xFF, 0xFA, 0xCA, 0x5E)),
                _ => new SolidColorBrush(Color.FromArgb(0xFF, 0x56, 0xD3, 0x64))
            };

            RiskScoreText.Text = $"{report.RiskScore}/100";
            RiskScoreText.Foreground = report.RiskScore switch
            {
                >= 50 => new SolidColorBrush(Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
                >= 20 => new SolidColorBrush(Color.FromArgb(0xFF, 0xFA, 0xCA, 0x5E)),
                _ => new SolidColorBrush(Color.FromArgb(0xFF, 0x56, 0xD3, 0x64))
            };

            EntropyText.Text = $"{report.Metrics.ShannonEntropy:F2}";
            EntropyText.Foreground = report.Metrics.IsHighEntropy
                ? new SolidColorBrush(Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72))
                : new SolidColorBrush(Color.FromArgb(0xFF, 0x76, 0xDD, 0xF5));

            // Update Sample Header Bar
            FileSizeLabel.Text = $"Size: {report.Metrics.FileSizeBytes:N0} bytes ({report.Metrics.FileSizeBytes / 1024.0 / 1024.0:F2} MiB)";
            FormatLabel.Text = report.PeDetails.IsPortableExecutable
                ? $"Format: PE ({report.PeDetails.Architecture}, {report.PeDetails.SectionCount} sections)"
                : "Format: Non-PE / Script or Binary";
            Sha256Label.Text = $"SHA-256: {report.Metrics.Sha256}";

            // Update Indicators List
            IndicatorRows.Clear();
            foreach (var ind in report.TriggeredIndicators)
            {
                IndicatorRows.Add(new SandboxIndicatorRow(ind));
            }
            IndicatorSummaryText.Text = $"{report.TriggeredIndicators.Count} indicator(s) detected";
            EmptyIndicatorsText.Visibility = report.TriggeredIndicators.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            // Update Risk Reasons & Report Box
            RiskReasonsText.Text = report.RiskReasons.Count > 0
                ? string.Join("\n• ", report.RiskReasons.Prepend(string.Empty)).TrimStart()
                : "No elevated risk factors detected. Sample exhibits normal structure.";

            ThreatReportBox.Text = SafeFileSandbox.GenerateTextReport(report);

            StatusHeadline.Text = $"Static Analysis Complete - {report.Verdict}";
            StatusDetail.Text = $"Analyzed '{report.Metrics.FileName}' with {report.TriggeredIndicators.Count} indicator(s) triggered. Risk score: {report.RiskScore}/100.";
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Analysis Failed";
            StatusDetail.Text = ex.Message;
        }
        finally
        {
            _analysisInFlight = false;
            BrowseButton.IsEnabled = true;
            AnalyzeButton.IsEnabled = true;
        }
    }

    private async void Detonate_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new ContentDialog
            {
                Title = "Host Detonation Guarded",
                Content = "Dynamic detonation on the host operating system is strictly disabled under Downpour's least-privilege security policy (AGENTS.md & SECURITY.md).\r\n\r\nRunning untrusted or malicious binaries requires an isolated Hyper-V / Windows Sandbox container broker (DN-008).\r\n\r\nComprehensive static inspection (Shannon entropy, PE structural validation, W^X violations, and API pattern scoring) is safely available via 'Analyze Static Only'.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await dialog.ShowAsync();
        }
        catch
        {
            StatusHeadline.Text = "Host Detonation Guarded";
            StatusDetail.Text = "Dynamic execution on the host is disabled under least-privilege security policy. Use 'Analyze Static Only'.";
        }
    }

    private async void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        if (_latestReport is null)
        {
            StatusDetail.Text = "Please analyze a sample before exporting a threat report.";
            return;
        }

        try
        {
            var ts = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var targetDir = Directory.Exists(desktopDir) ? desktopDir : AppContext.BaseDirectory;
            var outPath = Path.Combine(targetDir, $"downpour_sandbox_report_{ts}.txt");

            var text = SafeFileSandbox.GenerateTextReport(_latestReport);
            await File.WriteAllTextAsync(outPath, text, Encoding.UTF8);

            StatusHeadline.Text = "Threat Report Exported";
            StatusDetail.Text = $"Saved report to: {outPath}";
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Export failed";
            StatusDetail.Text = ex.Message;
        }
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        _latestReport = null;
        FilePathBox.Text = string.Empty;
        VerdictText.Text = "—";
        VerdictText.Foreground = new SolidColorBrush(Color.FromArgb(0xFF, 0x60, 0xDB, 0xEE));
        RiskScoreText.Text = "—";
        RiskScoreText.Foreground = new SolidColorBrush(Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72));
        EntropyText.Text = "—";
        EntropyText.Foreground = new SolidColorBrush(Color.FromArgb(0xFF, 0x76, 0xDD, 0xF5));
        FileSizeLabel.Text = "Size: —";
        FormatLabel.Text = "Format: —";
        Sha256Label.Text = "SHA-256: —";
        IndicatorSummaryText.Text = "0 indicators";
        IndicatorRows.Clear();
        EmptyIndicatorsText.Visibility = Visibility.Visible;
        RiskReasonsText.Text = "—";
        ThreatReportBox.Text = string.Empty;
        StatusHeadline.Text = "File Sandbox Ready";
        StatusDetail.Text = "Select an executable (.exe, .dll, .sys), script, or binary file to compute Shannon entropy, cryptographic hashes, and behavioral indicators.";
    }
}

public sealed class SandboxIndicatorRow
{
    public string Category { get; }
    public string Indicator { get; }
    public string Description { get; }
    public string WeightDisplay { get; }
    public SolidColorBrush CategoryBackground { get; }
    public SolidColorBrush CategoryForeground { get; }

    public SandboxIndicatorRow(SandboxTriggeredIndicator indicator)
    {
        Category = indicator.Category;
        Indicator = indicator.Indicator;
        Description = indicator.Description;
        WeightDisplay = $"+{indicator.Weight} pts";

        var (bg, fg) = indicator.Category switch
        {
            "Process Injection" => (Color.FromArgb(0x33, 0xFF, 0x55, 0x55), Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
            "Spyware / Keylogger" => (Color.FromArgb(0x33, 0xD2, 0x99, 0x22), Color.FromArgb(0xFF, 0xFA, 0xCA, 0x5E)),
            "Defense Evasion" => (Color.FromArgb(0x33, 0xBC, 0x8C, 0xFF), Color.FromArgb(0xFF, 0xD2, 0xA8, 0xFF)),
            "Credential Access" => (Color.FromArgb(0x33, 0xFF, 0x55, 0x55), Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
            "Packaging" => (Color.FromArgb(0x33, 0x58, 0xA6, 0xFF), Color.FromArgb(0xFF, 0x76, 0xDD, 0xF5)),
            "Memory Protection" => (Color.FromArgb(0x33, 0xD2, 0x99, 0x22), Color.FromArgb(0xFF, 0xFA, 0xCA, 0x5E)),
            "Packer Identification" => (Color.FromArgb(0x33, 0x58, 0xA6, 0xFF), Color.FromArgb(0xFF, 0x76, 0xDD, 0xF5)),
            _ => (Color.FromArgb(0x22, 0x60, 0xDB, 0xEE), Color.FromArgb(0xFF, 0x60, 0xDB, 0xEE))
        };
        CategoryBackground = new SolidColorBrush(bg);
        CategoryForeground = new SolidColorBrush(fg);
    }
}
