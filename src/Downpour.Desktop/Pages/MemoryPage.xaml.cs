using System.Collections.ObjectModel;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class MemoryPage : Page
{
    private MemoryForensicsSummary? _latestSummary;
    private readonly List<ProcessMemoryRow> _allProcesses = [];
    private bool _inFlight;
    private bool _filterThreatsOnly;
    private bool _isMonitoring;
    private DispatcherQueueTimer? _monitorTimer;

    public ObservableCollection<ProcessMemoryRow> VisibleProcesses { get; } = [];

    public MemoryPage()
    {
        InitializeComponent();
        ProcessesList.SelectionChanged += ProcessesList_SelectionChanged;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (_latestSummary is null)
        {
            await ScanProcessesAsync();
        }
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        StopMonitoring();
        base.OnNavigatedFrom(e);
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        await ScanProcessesAsync();
    }

    private void ToggleMonitor_Click(object sender, RoutedEventArgs e)
    {
        if (_isMonitoring)
        {
            StopMonitoring();
        }
        else
        {
            StartMonitoring();
        }
    }

    private void StartMonitoring()
    {
        _isMonitoring = true;
        ToggleMonitorButton.Content = "Stop Monitor";
        StatusHeadline.Text = "Auto-Monitor Active (60s Cadence)";
        StatusDetail.Text = "Continuously evaluating process memory regions and injection vectors every 60 seconds.";

        _monitorTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _monitorTimer.Interval = TimeSpan.FromSeconds(60);
        _monitorTimer.IsRepeating = true;
        _monitorTimer.Tick += async (_, _) => await ScanProcessesAsync();
        _monitorTimer.Start();
    }

    private void StopMonitoring()
    {
        _isMonitoring = false;
        _monitorTimer?.Stop();
        _monitorTimer = null;
        ToggleMonitorButton.Content = "Start Auto-Monitor";
        StatusHeadline.Text = "Auto-Monitor Stopped";
        StatusDetail.Text = "Recurring memory scanning is paused. Current inspection results are retained.";
    }

    private async Task ScanProcessesAsync()
    {
        if (_inFlight) return;
        _inFlight = true;
        ScanButton.IsEnabled = false;
        StatusHeadline.Text = "Scanning Process Memory...";
        StatusDetail.Text = "Walking running processes, scoring executable paths, thread configurations, and cross-referencing injection alerts...";

        try
        {
            var summary = await MemoryForensicsInspector.ScanAsync();
            _latestSummary = summary;

            TotalScannedText.Text = $"{summary.TotalProcessesScanned:N0}";
            InjectedCountText.Text = $"{summary.InjectedCount}";
            SuspiciousCountText.Text = $"{summary.SuspiciousCount}";
            CleanCountText.Text = $"{summary.CleanCount:N0}";

            StatusHeadline.Text = summary.InjectedCount > 0
                ? $"Process Injection Alert: {summary.InjectedCount} high-risk processes detected"
                : $"Memory Scan Complete: {summary.TotalProcessesScanned} processes evaluated";

            StatusDetail.Text = summary.InjectedCount > 0
                ? $"Detected {summary.InjectedCount} injected and {summary.SuspiciousCount} suspicious processes. Review findings table."
                : $"Nominal memory posture across {summary.TotalProcessesScanned} processes. No active hollowing or unbacked injection vectors.";

            _allProcesses.Clear();
            foreach (var proc in summary.AllInspections)
            {
                _allProcesses.Add(new ProcessMemoryRow(proc));
            }

            ApplyFilter();
            MemoryReportBox.Text = MemoryForensicsInspector.GenerateReport(summary);
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Memory Scan Error";
            StatusDetail.Text = ex.Message;
        }
        finally
        {
            _inFlight = false;
            ScanButton.IsEnabled = true;
        }
    }

    private void ProcessSearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        ApplyFilter();
    }

    private void FilterAll_Click(object sender, RoutedEventArgs e)
    {
        _filterThreatsOnly = false;
        FilterAllButton.Style = (Style)Application.Current.Resources["AccentButtonStyle"];
        FilterThreatsButton.Style = (Style)Application.Current.Resources["DefaultButtonStyle"];
        ApplyFilter();
    }

    private void FilterThreats_Click(object sender, RoutedEventArgs e)
    {
        _filterThreatsOnly = true;
        FilterThreatsButton.Style = (Style)Application.Current.Resources["AccentButtonStyle"];
        FilterAllButton.Style = (Style)Application.Current.Resources["DefaultButtonStyle"];
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var query = ProcessSearchBox.Text?.Trim() ?? string.Empty;

        var filtered = _allProcesses.AsEnumerable();

        if (_filterThreatsOnly)
        {
            filtered = filtered.Where(p => p.Severity != "CLEAN");
        }

        if (!string.IsNullOrEmpty(query))
        {
            filtered = filtered.Where(p =>
                p.ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                p.ProcessId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase) ||
                p.ExecutablePath.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                p.TechniqueDisplay.Contains(query, StringComparison.OrdinalIgnoreCase));
        }

        VisibleProcesses.Clear();
        foreach (var item in filtered)
        {
            VisibleProcesses.Add(item);
        }

        EmptyProcessesText.Visibility = VisibleProcesses.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ProcessesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ProcessesList.SelectedItem is ProcessMemoryRow selected)
        {
            SelectedProcessTitle.Text = $"{selected.ProcessName} (PID {selected.ProcessId}) — Score: {selected.ScoreDisplay} [{selected.Severity}]";
            SelectedProcessPath.Text = $"Path: {selected.ExecutablePath}\nMemory: {selected.MemoryDisplay}\nSuspected Vector: {selected.TechniqueDisplay}";

            SelectedProcessFindings.Text = selected.Findings.Count > 0
                ? "Findings:\n• " + string.Join("\n• ", selected.Findings)
                : "No abnormal memory or path characteristics detected.";
        }
    }

    private async void KillProcess_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var target = ProcessesList.SelectedItem as ProcessMemoryRow;
            var targetInfo = target is not null
                ? $"Selected target: {target.ProcessName} (PID {target.ProcessId}).\r\n\r\n"
                : "No specific process currently selected.\r\n\r\n";

            var dialog = new ContentDialog
            {
                Title = "Process Termination Guarded",
                Content = $"{targetInfo}Process termination, thread suspension, and memory modification are guarded under Downpour's least-privilege security policy (AGENTS.md & SECURITY.md).\r\n\r\nKilling processes requires an audited action broker (DN-008) with authenticated operator consent.\r\n\r\nPassive volatile memory inspection and injection pattern scoring remain active.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await dialog.ShowAsync();
        }
        catch
        {
            StatusHeadline.Text = "Process Termination Guarded";
            StatusDetail.Text = "Process killing is disabled pending audited action broker (DN-008).";
        }
    }

    private async void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        if (_latestSummary is null)
        {
            StatusDetail.Text = "Please scan processes before exporting a memory report.";
            return;
        }

        try
        {
            var ts = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var targetDir = Directory.Exists(desktopDir) ? desktopDir : AppContext.BaseDirectory;
            var outPath = Path.Combine(targetDir, $"downpour_memory_forensics_report_{ts}.txt");

            var text = MemoryForensicsInspector.GenerateReport(_latestSummary);
            await File.WriteAllTextAsync(outPath, text, Encoding.UTF8);

            StatusHeadline.Text = "Memory Report Exported";
            StatusDetail.Text = $"Saved report to: {outPath}";
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Export failed";
            StatusDetail.Text = ex.Message;
        }
    }
}

public sealed class ProcessMemoryRow
{
    public int ProcessId { get; }
    public string ProcessName { get; }
    public string PidDisplay { get; }
    public string ExecutablePath { get; }
    public string Severity { get; }
    public string ScoreDisplay { get; }
    public string MemoryDisplay { get; }
    public string TechniqueDisplay { get; }
    public IReadOnlyList<string> Findings { get; }
    public SolidColorBrush SeverityBackground { get; }
    public SolidColorBrush SeverityForeground { get; }

    public ProcessMemoryRow(ProcessMemoryInspection proc)
    {
        ProcessId = proc.ProcessId;
        ProcessName = proc.ProcessName;
        PidDisplay = $"PID {proc.ProcessId}";
        ExecutablePath = proc.ExecutablePath;
        Severity = proc.Severity;
        ScoreDisplay = $"{proc.InjectionScore}/100";
        MemoryDisplay = $"{proc.WorkingSetBytes / 1024.0 / 1024.0:F1} MiB · {proc.ThreadCount} thr";
        TechniqueDisplay = proc.SuspectedTechnique != "None" ? proc.SuspectedTechnique : "Normal Executable";
        Findings = proc.Findings;

        var (bg, fg) = proc.Severity switch
        {
            "CRITICAL" => (Color.FromArgb(0x33, 0xFF, 0x55, 0x55), Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
            "HIGH" => (Color.FromArgb(0x33, 0xD2, 0x99, 0x22), Color.FromArgb(0xFF, 0xFA, 0xCA, 0x5E)),
            "MEDIUM" => (Color.FromArgb(0x33, 0xBC, 0x8C, 0xFF), Color.FromArgb(0xFF, 0xD2, 0xA8, 0xFF)),
            "LOW" => (Color.FromArgb(0x33, 0x58, 0xA6, 0xFF), Color.FromArgb(0xFF, 0x76, 0xDD, 0xF5)),
            _ => (Color.FromArgb(0x33, 0x3F, 0xB9, 0x50), Color.FromArgb(0xFF, 0x56, 0xD3, 0x64))
        };
        SeverityBackground = new SolidColorBrush(bg);
        SeverityForeground = new SolidColorBrush(fg);
    }
}
