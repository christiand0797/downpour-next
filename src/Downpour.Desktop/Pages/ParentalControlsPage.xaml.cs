using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour_Desktop.Pages;

public sealed partial class ParentalControlsPage : Page
{
    private readonly ParentalControlsManager _manager = new();
    private readonly List<ParentalActivityLogEntry> _activityLogs = [];
    private ParentalPostureSnapshot? _currentSnapshot;

    public ParentalControlsPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        LoadConfigIntoUi();
        RefreshPosture();
    }

    private void LoadConfigIntoUi()
    {
        var config = _manager.CurrentConfig;

        MasterEnableCheckBox.IsChecked = config.Enabled;
        ProfileNameBox.Text = config.ProfileName;

        // Screen time
        ScreenTimeEnableCheckBox.IsChecked = config.ScreenTime.Enabled;
        WeekdayLimitBox.Text = config.ScreenTime.WeekdayLimitMinutes.ToString();
        WeekendLimitBox.Text = config.ScreenTime.WeekendLimitMinutes.ToString();
        BedtimeStartBox.Text = config.ScreenTime.BedtimeStart;
        BedtimeEndBox.Text = config.ScreenTime.BedtimeEnd;

        // Web filter
        WebFilterEnableCheckBox.IsChecked = config.WebFilter.Enabled;
        BlockAdultCheckBox.IsChecked = config.WebFilter.BlockAdultContent;
        BlockGamblingCheckBox.IsChecked = config.WebFilter.BlockGambling;
        BlockViolenceCheckBox.IsChecked = config.WebFilter.BlockViolence;
        BlockWeaponsCheckBox.IsChecked = config.WebFilter.BlockWeapons;
        BlockDrugsCheckBox.IsChecked = config.WebFilter.BlockDrugs;

        // App restrictions
        AppRestrictionEnableCheckBox.IsChecked = config.AppRestrictions.Enabled;
        ConfiguredAppsListText.Text = string.Join(", ", config.AppRestrictions.BlockedExecutableNames);

        UpdateMasterBadge(config.Enabled);
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshPosture();
    }

    private void RefreshPosture()
    {
        try
        {
            int simUsage = (int)(UsageSimSlider?.Value ?? 45);
            _currentSnapshot = _manager.CapturePostureSnapshot(currentUsageMinutes: simUsage, logs: _activityLogs);

            UpdateUiWithSnapshot(_currentSnapshot);
            AppendLog("Posture Check", $"Parental controls posture evaluated for '{_currentSnapshot.Config.ProfileName}'. Curfew: {(_currentSnapshot.ScreenTime.IsWithinCurfew ? "Active" : "Inactive")}.", "Info");
        }
        catch (Exception ex)
        {
            AppendLog("Posture Error", ex.Message, "Alert");
        }
    }

    private void UpdateUiWithSnapshot(ParentalPostureSnapshot snapshot)
    {
        // Screen time metrics
        MetricScreenTimeUsage.Text = $"{snapshot.ScreenTime.TodayUsageMinutes} / {snapshot.ScreenTime.TodayLimitMinutes} min";
        MetricScreenTimeRemaining.Text = $"{snapshot.ScreenTime.RemainingMinutes} min remaining";

        if (snapshot.ScreenTime.IsLimitExceeded)
        {
            MetricScreenTimeUsage.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 239, 68, 68));
            MetricScreenTimeRemaining.Text = "DAILY LIMIT EXCEEDED";
        }
        else
        {
            MetricScreenTimeUsage.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 56, 189, 248));
        }

        // Bedtime curfew metrics
        MetricBedtimeWindow.Text = $"{snapshot.Config.ScreenTime.BedtimeStart} - {snapshot.Config.ScreenTime.BedtimeEnd}";
        if (snapshot.ScreenTime.IsWithinCurfew)
        {
            MetricCurfewStatus.Text = "CURFEW ACTIVE";
            MetricCurfewStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 239, 68, 68));
            CurfewBanner.Text = "Bedtime: CURFEW ACTIVE";
            CurfewBanner.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 239, 68, 68));
        }
        else
        {
            MetricCurfewStatus.Text = "Access Active";
            MetricCurfewStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
            CurfewBanner.Text = "Bedtime: Open Access";
            CurfewBanner.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }

        // Web filter metrics
        var blockedDomains = ParentalControlsManager.GetDomainsToBlock(snapshot.Config.WebFilter);
        int categoryCount = 0;
        if (snapshot.Config.WebFilter.BlockAdultContent) categoryCount++;
        if (snapshot.Config.WebFilter.BlockGambling) categoryCount++;
        if (snapshot.Config.WebFilter.BlockViolence) categoryCount++;
        if (snapshot.Config.WebFilter.BlockWeapons) categoryCount++;
        if (snapshot.Config.WebFilter.BlockDrugs) categoryCount++;

        MetricBlockedCategories.Text = $"{categoryCount} Categories";
        MetricBlockedDomainsCount.Text = $"{blockedDomains.Count} domains cataloged";

        // Hosts status
        if (snapshot.HostsPosture.HasDownpourFilterMarker)
        {
            MetricHostsStatus.Text = "APPLIED";
            MetricHostsStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }
        else
        {
            MetricHostsStatus.Text = "NOT APPLIED";
            MetricHostsStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 156, 163, 175));
        }

        // App restrictions check
        if (snapshot.RestrictedAppsRunning.Count > 0)
        {
            RestrictedAppsStatusText.Text = $"Restricted application(s) detected running: {string.Join(", ", snapshot.RestrictedAppsRunning)}";
            RestrictedAppsStatusText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 248, 113, 113));
        }
        else
        {
            RestrictedAppsStatusText.Text = "Running restricted applications check: None detected.";
            RestrictedAppsStatusText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }
    }

    private void UpdateMasterBadge(bool enabled)
    {
        if (enabled)
        {
            MasterBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 6, 95, 70));
            MasterBadge.BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 5, 150, 105));
            MasterBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 110, 231, 183));
            MasterBadgeText.Text = "ACTIVE";
        }
        else
        {
            MasterBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 30, 41, 59));
            MasterBadge.BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 51, 65, 85));
            MasterBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 148, 163, 184));
            MasterBadgeText.Text = "DISABLED";
        }
    }

    private async void SaveSettingsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            int weekdayLimit = int.TryParse(WeekdayLimitBox.Text, out int wd) ? wd : 120;
            int weekendLimit = int.TryParse(WeekendLimitBox.Text, out int we) ? we : 240;

            var newConfig = new ParentalControlsConfig(
                Enabled: MasterEnableCheckBox.IsChecked ?? true,
                ProfileName: string.IsNullOrWhiteSpace(ProfileNameBox.Text) ? "Child Profile" : ProfileNameBox.Text.Trim(),
                ScreenTime: new ScreenTimeSchedule(
                    Enabled: ScreenTimeEnableCheckBox.IsChecked ?? true,
                    WeekdayLimitMinutes: weekdayLimit,
                    WeekendLimitMinutes: weekendLimit,
                    BedtimeStart: BedtimeStartBox.Text.Trim(),
                    BedtimeEnd: BedtimeEndBox.Text.Trim()),
                WebFilter: new WebFilterPolicy(
                    Enabled: WebFilterEnableCheckBox.IsChecked ?? true,
                    BlockAdultContent: BlockAdultCheckBox.IsChecked ?? true,
                    BlockGambling: BlockGamblingCheckBox.IsChecked ?? true,
                    BlockViolence: BlockViolenceCheckBox.IsChecked ?? true,
                    BlockWeapons: BlockWeaponsCheckBox.IsChecked ?? true,
                    BlockDrugs: BlockDrugsCheckBox.IsChecked ?? true,
                    CustomBlockedDomains: _manager.CurrentConfig.WebFilter.CustomBlockedDomains,
                    SafeSearchEnforced: true),
                AppRestrictions: new AppRestrictionPolicy(
                    Enabled: AppRestrictionEnableCheckBox.IsChecked ?? true,
                    BlockedExecutableNames: _manager.CurrentConfig.AppRestrictions.BlockedExecutableNames,
                    MonitoredProfileUsername: string.Empty));

            _manager.SaveConfig(newConfig);
            UpdateMasterBadge(newConfig.Enabled);
            RefreshPosture();

            AppendLog("Settings Saved", $"Parental controls configuration saved for '{newConfig.ProfileName}'.", "Info");

            var dialog = new ContentDialog
            {
                Title = "Settings Saved",
                Content = new TextBlock
                {
                    Text = "Parental controls configuration has been saved successfully.\n\nScreen time limits, bedtime curfew, and web filter categories have been updated.",
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await dialog.ShowAsync();
        }
        catch (Exception ex)
        {
            AppendLog("Save Failed", ex.Message, "Alert");
        }
    }

    private async void ApplyWebFilterButton_Click(object sender, RoutedEventArgs e)
    {
        var domains = ParentalControlsManager.GetDomainsToBlock(_manager.CurrentConfig.WebFilter);
        AppendLog("Web Filter Action", $"Apply web filter requested ({domains.Count} domains). Guarded under DN-008.", "Warning");

        var dialog = new ContentDialog
        {
            Title = "Web Filter Guarded (DN-008)",
            Content = new TextBlock
            {
                Text = $"Writing DNS block entries ({domains.Count} domains across configured categories) to the Windows hosts file (C:\\Windows\\System32\\drivers\\etc\\hosts) is guarded under least-privilege security policy.\n\nModifying system driver files requires an elevated Action Broker authorization token (DN-008). In read-only mode, the domain blocklist was evaluated without modifying your hosts file.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "Understood",
            XamlRoot = XamlRoot
        };
        await dialog.ShowAsync();
    }

    private async void RemoveWebFilterButton_Click(object sender, RoutedEventArgs e)
    {
        AppendLog("Web Filter Action", "Remove web filter requested. Guarded under DN-008.", "Warning");

        var dialog = new ContentDialog
        {
            Title = "Remove Filter Guarded (DN-008)",
            Content = new TextBlock
            {
                Text = "Stripping DNS entries from the Windows hosts file requires administrator elevation and an authorized Action Broker token under DN-008.\n\nIn read-only mode, system files are preserved.",
                TextWrapping = TextWrapping.Wrap
            },
            CloseButtonText = "Understood",
            XamlRoot = XamlRoot
        };
        await dialog.ShowAsync();
    }

    private async void ExportReportButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_currentSnapshot is null)
            {
                _currentSnapshot = _manager.CapturePostureSnapshot(logs: _activityLogs);
            }

            string reportContent = _manager.GenerateParentalPostureReport(_currentSnapshot, _activityLogs);
            string desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string filePath = Path.Combine(desktopDir, $"Downpour_Parental_Controls_Report.md");

            await File.WriteAllTextAsync(filePath, reportContent);
            AppendLog("Export Report", $"Family Safety Posture Report exported to Desktop: {Path.GetFileName(filePath)}", "Info");

            var dialog = new ContentDialog
            {
                Title = "Parental Controls Report Exported",
                Content = new TextBlock
                {
                    Text = $"The Parental Controls Posture Report has been exported to your Desktop:\n\n{filePath}\n\nIncludes screen time limits, bedtime curfew status, blocked web categories, and application restriction posture.",
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = "OK",
                XamlRoot = XamlRoot
            };
            await dialog.ShowAsync();
        }
        catch (Exception ex)
        {
            AppendLog("Export Failed", ex.Message, "Alert");
        }
    }

    private void MasterEnableCheckBox_Checked(object sender, RoutedEventArgs e)
    {
        UpdateMasterBadge(true);
    }

    private void MasterEnableCheckBox_Unchecked(object sender, RoutedEventArgs e)
    {
        UpdateMasterBadge(false);
    }

    private void UsageSimSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (UsageSimText is not null)
        {
            UsageSimText.Text = $"{(int)e.NewValue} min";
        }
        RefreshPosture();
    }

    private void ClearLogButton_Click(object sender, RoutedEventArgs e)
    {
        _activityLogs.Clear();
        LogTextBox.Text = string.Empty;
        AppendLog("Event Log", "Parental controls activity log cleared.", "Info");
    }

    private void AppendLog(string action, string message, string severity)
    {
        var entry = new ParentalActivityLogEntry(DateTimeOffset.UtcNow, action, severity, message);
        _activityLogs.Add(entry);

        string severityTag = severity.ToUpperInvariant() switch
        {
            "ALERT" => "[ALERT]",
            "WARNING" => "[WARN]",
            _ => "[INFO]"
        };

        string logLine = $"[{entry.TimestampUtc:HH:mm:ss}] {severityTag} {action}: {message}\n";
        LogTextBox.Text = logLine + LogTextBox.Text;
    }
}
