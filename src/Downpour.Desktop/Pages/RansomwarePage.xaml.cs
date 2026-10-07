using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class RansomwarePage : Page
{
    private RansomwareDefensePosture? _latestPosture;
    private bool _inFlight;

    public ObservableCollection<RansomwareDirectoryRow> DirectoryRows { get; } = [];
    public ObservableCollection<RansomwareCanaryRow> CanaryRows { get; } = [];
    public ObservableCollection<RansomwareIndicatorRow> IndicatorRows { get; } = [];

    public RansomwarePage()
    {
        InitializeComponent();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (_latestPosture is null)
        {
            await RefreshPostureAsync();
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        await RefreshPostureAsync();
    }

    private async Task RefreshPostureAsync()
    {
        if (_inFlight) return;
        _inFlight = true;
        RefreshButton.IsEnabled = false;
        DeployCanaryButton.IsEnabled = false;
        StatusHeadline.Text = "Evaluating Ransomware Defense Posture...";
        StatusDetail.Text = "Scanning protected directories, inspecting canary token decoys, and checking Volume Shadow Copy (VSS) status...";

        try
        {
            var posture = await RansomwareDefenseInspector.InspectAsync(sampleContents: AppPreferences.RansomwareContentSampling);
            _latestPosture = posture;

            // Overview counters
            OverallStatusText.Text = posture.OverallStatus switch
            {
                "UNDER_ATTACK" => "UNDER ATTACK",
                "ELEVATED_RISK" => "ELEVATED RISK",
                _ => "PROTECTED"
            };

            var statusColor = posture.OverallStatus switch
            {
                "UNDER_ATTACK" => Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72),
                "ELEVATED_RISK" => Color.FromArgb(0xFF, 0xFA, 0xCA, 0x5E),
                _ => Color.FromArgb(0xFF, 0x56, 0xD3, 0x64)
            };
            OverallStatusText.Foreground = new SolidColorBrush(statusColor);

            ProtectedDirsCountText.Text = $"{posture.ProtectedDirectories.Count}";
            FilesMonitoredCountText.Text = $"{posture.TotalFilesMonitored:N0}";
            ThreatIndicatorsCountText.Text = $"{posture.ThreatIndicators.Count}";
            ThreatIndicatorsCountText.Foreground = posture.ThreatIndicators.Count > 0
                ? new SolidColorBrush(Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72))
                : new SolidColorBrush(Color.FromArgb(0xFF, 0x56, 0xD3, 0x64));

            StatusHeadline.Text = posture.OverallStatus switch
            {
                "UNDER_ATTACK" => "High-Severity Ransomware Activity Detected!",
                "ELEVATED_RISK" => "Ransomware Defense Warning: Elevated Risk Factors",
                _ => "Ransomware Defense Active & Protected"
            };

            StatusDetail.Text = posture.ThreatIndicators.Count == 0
                ? $"Monitored {posture.TotalFilesMonitored:N0} files across {posture.ProtectedDirectories.Count} directories. Canary decoys verified intact."
                : $"Detected {posture.ThreatIndicators.Count} potential threat indicator(s). Review activity log and indicators list.";

            // Protected Directory Rows
            DirectoryRows.Clear();
            foreach (var d in posture.ProtectedDirectories)
            {
                DirectoryRows.Add(new RansomwareDirectoryRow(d));
            }

            // Canary Rows
            CanaryRows.Clear();
            foreach (var c in posture.Canaries)
            {
                CanaryRows.Add(new RansomwareCanaryRow(c));
            }
            CanarySummaryText.Text = $"{posture.Canaries.Count} canary decoy(s)";

            // Indicator Rows
            IndicatorRows.Clear();
            foreach (var ind in posture.ThreatIndicators)
            {
                IndicatorRows.Add(new RansomwareIndicatorRow(ind));
            }
            EmptyIndicatorsText.Visibility = posture.ThreatIndicators.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            // VSS Card
            var vss = posture.VssPosture;
            var vssText = $"VSS Service State: {vss.VssServiceStatus} | Anti-Recovery: {(vss.HasRecentVssTampering ? "TAMPERING FLAGGED" : "Nominal")}";
            if (vss.TamperingEvidence.Count > 0)
            {
                vssText += $"\nEvidence: {string.Join("; ", vss.TamperingEvidence)}";
            }
            VssDetailText.Text = vssText;

            // Report Box
            DefenseReportBox.Text = RansomwareDefenseInspector.GenerateReport(posture);
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Posture Inspection Error";
            StatusDetail.Text = ex.Message;
        }
        finally
        {
            _inFlight = false;
            RefreshButton.IsEnabled = true;
            DeployCanaryButton.IsEnabled = true;
        }
    }

    private async void DeployCanaries_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var canaryStoreDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Downpour", "Canaries");
            Directory.CreateDirectory(canaryStoreDir);

            string[] names =
            [
                "!_Budget_2026_FINAL.xlsx.canary",
                "!_Contract_Draft_v3.docx.canary",
                "!_Annual_Report.pdf.canary",
                "!_Client_Database.csv.canary",
                "!_Passwords.txt.canary"
            ];

            foreach (var name in names)
            {
                var filePath = Path.Combine(canaryStoreDir, name);
                if (!File.Exists(filePath))
                {
                    var data = new byte[512];
                    RandomNumberGenerator.Fill(data);
                    // Add benign magic header
                    data[0] = (byte)'P';
                    data[1] = (byte)'K';
                    data[2] = 0x03;
                    data[3] = 0x04;
                    await File.WriteAllBytesAsync(filePath, data);
                }
            }

            StatusHeadline.Text = "Canaries Deployed";
            StatusDetail.Text = $"Created {names.Length} canary decoys in local store. Re-evaluating posture...";
            await RefreshPostureAsync();
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Canary Deployment Failed";
            StatusDetail.Text = ex.Message;
        }
    }

    private async void Rollback_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new ContentDialog
            {
                Title = "File Rollback Guarded",
                Content = "Automated file rollback and Volume Shadow Copy (VSS) snapshot restoration are strictly guarded under Downpour's least-privilege security policy (AGENTS.md & SECURITY.md).\r\n\r\nRestoring system volumes or overwriting files requires an audited action broker (DN-008) with verifiable operator consent and rollback proof.\r\n\r\nDecoy canary monitoring, anti-recovery detection, and passive entropy disruption analysis remain active.",
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await dialog.ShowAsync();
        }
        catch
        {
            StatusHeadline.Text = "Rollback Guarded";
            StatusDetail.Text = "Automated file restoration is disabled pending audited action broker (DN-008).";
        }
    }

    private async void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        if (_latestPosture is null)
        {
            StatusDetail.Text = "Please evaluate posture before exporting a report.";
            return;
        }

        try
        {
            var ts = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var targetDir = Directory.Exists(desktopDir) ? desktopDir : AppContext.BaseDirectory;
            var outPath = Path.Combine(targetDir, $"downpour_ransomware_defense_report_{ts}.txt");

            var text = RansomwareDefenseInspector.GenerateReport(_latestPosture);
            await File.WriteAllTextAsync(outPath, text, Encoding.UTF8);

            StatusHeadline.Text = "Defense Report Exported";
            StatusDetail.Text = $"Saved report to: {outPath}";
        }
        catch (Exception ex)
        {
            StatusHeadline.Text = "Export failed";
            StatusDetail.Text = ex.Message;
        }
    }
}

public sealed class RansomwareDirectoryRow
{
    public string DisplayName { get; }
    public string Path { get; }
    public string StatsDisplay { get; }
    public string EntropyDisplay { get; }

    public RansomwareDirectoryRow(RansomwareProtectedDirectory directory)
    {
        DisplayName = directory.DisplayName;
        Path = directory.Path;
        StatsDisplay = $"{directory.FileCount:N0} files · {directory.TotalBytes / 1024.0 / 1024.0:F1} MiB";
        EntropyDisplay = directory.IsAccessible
            ? $"Entropy: {directory.AverageEntropy:F2} / 8.0"
            : "Inaccessible";
    }
}

public sealed class RansomwareCanaryRow
{
    public string FileName { get; }
    public string DirectoryPath { get; }
    public string Status { get; }
    public string EntropyDisplay { get; }
    public string VerifiedDisplay { get; }
    public SolidColorBrush StatusBackground { get; }
    public SolidColorBrush StatusForeground { get; }

    public RansomwareCanaryRow(RansomwareCanaryStatus canary)
    {
        FileName = canary.FileName;
        DirectoryPath = canary.DirectoryPath;
        Status = canary.Status;
        EntropyDisplay = canary.Exists ? $"Entropy: {canary.CurrentEntropy:F2}" : "—";
        VerifiedDisplay = canary.IntegrityVerified ? "Integrity OK" : "Unverified / Modified";

        var (bg, fg) = canary.Status switch
        {
            "Active" => (Color.FromArgb(0x33, 0x3F, 0xB9, 0x50), Color.FromArgb(0xFF, 0x56, 0xD3, 0x64)),
            "Encrypted" => (Color.FromArgb(0x33, 0xFF, 0x55, 0x55), Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
            "Tampered" => (Color.FromArgb(0x33, 0xFF, 0x55, 0x55), Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
            _ => (Color.FromArgb(0x33, 0x8B, 0x94, 0x9E), Color.FromArgb(0xFF, 0x8B, 0x94, 0x9E))
        };
        StatusBackground = new SolidColorBrush(bg);
        StatusForeground = new SolidColorBrush(fg);
    }
}

public sealed class RansomwareIndicatorRow
{
    public string Category { get; }
    public string Description { get; }
    public string TargetPath { get; }
    public string Severity { get; }
    public SolidColorBrush SeverityBackground { get; }
    public SolidColorBrush SeverityForeground { get; }

    public RansomwareIndicatorRow(RansomwareThreatIndicator indicator)
    {
        Category = indicator.Category;
        Description = indicator.Description;
        TargetPath = indicator.TargetPath;
        Severity = indicator.Severity;

        var (bg, fg) = indicator.Severity switch
        {
            "CRITICAL" => (Color.FromArgb(0x33, 0xFF, 0x55, 0x55), Color.FromArgb(0xFF, 0xFF, 0x7B, 0x72)),
            "HIGH" => (Color.FromArgb(0x33, 0xD2, 0x99, 0x22), Color.FromArgb(0xFF, 0xFA, 0xCA, 0x5E)),
            _ => (Color.FromArgb(0x33, 0x58, 0xA6, 0xFF), Color.FromArgb(0xFF, 0x76, 0xDD, 0xF5))
        };
        SeverityBackground = new SolidColorBrush(bg);
        SeverityForeground = new SolidColorBrush(fg);
    }
}
