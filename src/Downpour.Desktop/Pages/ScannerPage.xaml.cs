using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using System.Runtime.InteropServices;
using Windows.Storage.Pickers;

namespace Downpour_Desktop.Pages;

public sealed partial class ScannerPage : Page
{
    private bool _busy;
    private readonly YaraScanClient _yara = new();
    private readonly DispatcherTimer _yaraTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private Guid _renderedJob;
    private int _renderedFindings = -1;
    private bool _polling;

    public ScannerPage()
    {
        InitializeComponent();
        _yaraTimer.Tick += async (_, _) => await RefreshYaraAsync();
        Loaded += async (_, _) =>
        {
            await RefreshYaraAsync(ensureService: true);
            _yaraTimer.Start();
        };
        Unloaded += (_, _) => _yaraTimer.Stop();
    }

    private async Task RefreshYaraAsync(bool ensureService = false)
    {
        if (_polling) return;
        _polling = true;
        try
        {
            var status = await _yara.StatusAsync();
            if (status is null && ensureService)
            {
                await App.EnsureSensorServiceAsync();
                status = await _yara.StatusAsync();
            }
            RenderYara(status);
        }
        finally
        {
            _polling = false;
        }
    }

    private void RenderYara(YaraScanResponse? status)
    {
        if (status is null)
        {
            YaraEngineText.Text = "The sensor service is not reachable, so YARA scanning is unavailable.";
            SetYaraButtons(running: false, available: false);
            return;
        }
        var failed = status.RuleFiles?.Count(file => !file.Loaded) ?? 0;
        YaraEngineText.Text = status.EngineAvailable
            ? $"YARA-X {status.EngineVersion} · {status.RuleCount} rules loaded ({status.RuleCount - status.LowConfidenceRules} can raise alerts, {status.LowConfidenceRules} low confidence)"
              + (failed > 0 ? $" · {failed} rule file(s) failed to load" : "")
            : status.RuleFiles is null ? "Starting the scanner…" : "The scanner is unavailable. Start a scan to see the reason.";
        if (status.RuleFiles is { Count: > 0 } files)
            RuleFilesText.Text = string.Join("\n", files.Select(file => file.Loaded
                ? $"{file.File}: {file.RuleCount} rule(s){(file.RelaxedSyntax ? " (YARA-compatible regex mode)" : "")}"
                : $"{file.File}: NOT LOADED: {file.Error?.Split('\n').FirstOrDefault()}"));

        var job = status.Job;
        var running = job?.State is "starting" or "running";
        SetYaraButtons(running, status.EngineAvailable || status.RuleFiles is null);
        if (job is null)
        {
            YaraStatusText.Text = "";
            return;
        }
        YaraStatusText.Text = job.State switch
        {
            "starting" => "Starting the scanner…",
            "running" => $"Scanning {job.Root}: {job.FilesScanned:N0} scanned, {job.FilesSkipped:N0} skipped, {job.FilesFailed:N0} failed. Current: {job.CurrentFile}",
            "completed" => $"Finished {job.Root}: {job.FilesScanned:N0} scanned, {job.FilesSkipped:N0} skipped, {job.FilesFailed:N0} failed, {job.Findings.Count:N0} file(s) with matches.",
            "cancelled" => $"Cancelled after {job.FilesScanned:N0} files.",
            _ => $"The scan failed: {job.Message}",
        } + (job.State == "completed" && job.Message is { } note ? " " + note : "");
        if (job.JobId != _renderedJob || job.Findings.Count != _renderedFindings) RenderFindings(job);
    }

    private void RenderFindings(YaraScanJob job)
    {
        _renderedJob = job.JobId;
        _renderedFindings = job.Findings.Count;
        YaraFindingsPanel.Children.Clear();
        var secondary = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];
        foreach (var finding in job.Findings.OrderBy(f => f.Matches.All(m => m.LowConfidence)).Take(200))
        {
            var confident = finding.Matches.Count(m => !m.LowConfidence);
            var panel = new StackPanel { Spacing = 3 };
            panel.Children.Add(new TextBlock { Text = finding.Path, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            panel.Children.Add(new TextBlock
            {
                Text = confident > 0 ? $"Raised to triage · {confident} rule(s)" : "Low confidence only · not raised to triage",
                FontSize = 12,
                Foreground = new SolidColorBrush(confident > 0 ? Windows.UI.Color.FromArgb(0xFF, 0xFF, 0x8A, 0x80) : Windows.UI.Color.FromArgb(0xFF, 0x91, 0xAF, 0xC2)),
            });
            foreach (var match in finding.Matches.OrderBy(m => m.LowConfidence).Take(12))
                panel.Children.Add(new TextBlock
                {
                    Text = $"{match.Severity} · {match.Namespace}:{match.Rule}{(match.LowConfidence ? " (low confidence)" : "")}{(match.Description.Length > 0 ? " · " + match.Description : "")}",
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = secondary,
                });
            YaraFindingsPanel.Children.Add(new Border
            {
                Padding = new Thickness(12),
                CornerRadius = new CornerRadius(10),
                BorderThickness = new Thickness(1),
                BorderBrush = new SolidColorBrush(Windows.UI.Color.FromArgb(0x57, 0x38, 0xB9, 0xD1)),
                Background = new SolidColorBrush(Windows.UI.Color.FromArgb(0xC8, 0x08, 0x11, 0x1E)),
                Child = panel,
            });
        }
    }

    private void SetYaraButtons(bool running, bool available)
    {
        YaraFileButton.IsEnabled = !running && available;
        YaraFolderButton.IsEnabled = !running && available;
        YaraCancelButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        YaraProgress.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void YaraFile_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            var file = await picker.PickSingleFileAsync();
            if (file is not null && !string.IsNullOrEmpty(file.Path)) await StartYaraAsync(file.Path, false);
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            YaraStatusText.Text = $"The file picker could not be opened: {exception.Message}";
        }
    }

    private async void YaraFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FolderPicker();
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            var folder = await picker.PickSingleFolderAsync();
            if (folder is not null && !string.IsNullOrEmpty(folder.Path)) await StartYaraAsync(folder.Path, YaraRecursive.IsChecked == true);
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            YaraStatusText.Text = $"The folder picker could not be opened: {exception.Message}";
        }
    }

    private async Task StartYaraAsync(string path, bool recursive)
    {
        var response = await _yara.StartAsync(path, recursive);
        if (response is null) { YaraStatusText.Text = "The sensor service did not respond."; return; }
        if (!response.Accepted) { YaraStatusText.Text = response.Message; return; }
        _renderedFindings = -1;
        RenderYara(response);
    }

    private async void YaraCancel_Click(object sender, RoutedEventArgs e)
    {
        var response = await _yara.CancelAsync();
        if (response is not null) RenderYara(response);
    }

    private async void ChooseFile_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (_busy) return;
        Windows.Storage.StorageFile? file;
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".exe");
            picker.FileTypeFilter.Add(".dll");
            picker.FileTypeFilter.Add(".sys");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            file = await picker.PickSingleFileAsync();
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            InspectionStatus.Text = $"The file picker could not be opened: {exception.Message}";
            return;
        }
        if (file is null) return;

        _busy = true;
        ChooseFileButton.IsEnabled = false;
        InspectionProgress.IsActive = true;
        ResultCard.Visibility = Microsoft.UI.Xaml.Visibility.Collapsed;
        InspectionStatus.Text = "Reading and hashing the selected file…";
        try
        {
            var filePath = file.Path;
            var inspection = await Task.Run(() =>
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                    FileOptions.SequentialScan);
                return StaticFileInspector.Inspect(stream, file.Name);
            });
            FileNameText.Text = inspection.FileName;
            FileSizeText.Text = $"{inspection.FileSize:N0} bytes ({inspection.FileSize / 1024d / 1024d:F2} MiB)";
            HashText.Text = inspection.Sha256;
            FormatText.Text = inspection.IsPortableExecutable ? "Windows Portable Executable (PE)" : "Not recognized as a PE image";
            PeDetailsText.Text = inspection.IsPortableExecutable
                ? $"{inspection.Architecture} · {inspection.SectionCount} sections · {inspection.WritableExecutableSectionCount} writable + executable sections · " +
                  (inspection.PeTimestampUtc is { } timestamp ? $"header timestamp {timestamp:yyyy-MM-dd HH:mm:ss} UTC" : "no PE timestamp")
                : "No supported PE headers were present. SHA-256 was still calculated.";
            CertificateText.Text = inspection.IsPortableExecutable
                ? inspection.HasAuthenticodeCertificateTable ? "Present (not verified)" : "Not present (not a trust verdict)"
                : "Not applicable";
            ResultCard.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
            InspectionStatus.Text = "Static inspection complete. No safe/malicious verdict was produced.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            InspectionStatus.Text = $"Inspection failed: {exception.Message}";
        }
        finally
        {
            InspectionProgress.IsActive = false;
            ChooseFileButton.IsEnabled = true;
            _busy = false;
        }
    }
}
