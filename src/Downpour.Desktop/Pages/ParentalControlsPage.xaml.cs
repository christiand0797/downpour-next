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
    private ParentalControlsManager _manager = null!;
    private bool _busy;
    private bool _active;
    private readonly List<ParentalActivityLogEntry> _activityLogs = [];
    private ParentalPostureSnapshot? _currentSnapshot;

    public ParentalControlsPage()
    {
        InitializeComponent();
        MasterEnableCheckBox.Checked += MasterEnableCheckBox_Checked;
        MasterEnableCheckBox.Unchecked += MasterEnableCheckBox_Unchecked;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _active = true;
        await RunAsync(async () =>
        {
            _manager ??= await Task.Run(() => new ParentalControlsManager());
            if (!_active) return;
            LoadConfigIntoUi();
            if (_manager.ConfigurationWarning is { } warning) AppendLog("Configuration", warning, "Warning");
            await RefreshPosture();
        });
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _active = false;
        base.OnNavigatedFrom(e);
    }

    private async Task RunAsync(Func<Task> action)
    {
        if (_busy) return;
        _busy = true;
        RefreshButton.IsEnabled = SaveSettingsButton.IsEnabled = ExportReportButton.IsEnabled = false;
        try { await action(); }
        catch (Exception ex) { if (_active) AppendLog("Operation failed", ex.Message, "Alert"); }
        finally
        {
            _busy = false;
            RefreshButton.IsEnabled = SaveSettingsButton.IsEnabled = ExportReportButton.IsEnabled = true;
        }
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
        ConfiguredAppsBox.Text = string.Join(Environment.NewLine, config.AppRestrictions.BlockedExecutableNames);
        CustomDomainsBox.Text = string.Join(Environment.NewLine, config.WebFilter.CustomBlockedDomains);

        UpdateMasterBadge(config.Enabled);
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await RunAsync(RefreshPosture);

    private async Task RefreshPosture()
    {
        if (_manager is null) return;
        var logs = _activityLogs.ToArray();
        var snapshot = await Task.Run(() => _manager.CapturePostureSnapshot(logs: logs));
        if (!_active) return;
        _currentSnapshot = snapshot;
        UpdateUiWithSnapshot(snapshot);
        AppendLog("Posture", "Hosts and accessible processes reviewed. Screen-time usage is not measured.", "Info");
    }

    private void UpdateUiWithSnapshot(ParentalPostureSnapshot snapshot)
    {
        MetricScreenTimeUsage.Text = "Not measured";
        MetricScreenTimeRemaining.Text = $"Configured limit: {snapshot.ScreenTime.TodayLimitMinutes} min";

        // Bedtime curfew metrics
        MetricBedtimeWindow.Text = $"{snapshot.Config.ScreenTime.BedtimeStart} - {snapshot.Config.ScreenTime.BedtimeEnd}";
        if (snapshot.ScreenTime.IsWithinCurfew)
        {
            MetricCurfewStatus.Text = "Within bedtime · review only";
            MetricCurfewStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 239, 68, 68));
            CurfewBanner.Text = "Within configured bedtime";
            CurfewBanner.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 239, 68, 68));
        }
        else
        {
            MetricCurfewStatus.Text = "Outside bedtime · review only";
            MetricCurfewStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
            CurfewBanner.Text = "Outside configured bedtime";
            CurfewBanner.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }

        if (!snapshot.Config.Enabled || !snapshot.Config.ScreenTime.Enabled)
            MetricCurfewStatus.Text = CurfewBanner.Text = "Schedule disabled";

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
            MetricHostsStatus.Text = $"{snapshot.HostsPosture.ActiveBlockedDomainsCount} observed entries";
            MetricHostsStatus.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 52, 211, 153));
        }
        else
        {
            MetricHostsStatus.Text = snapshot.HostsPosture.IsAccessible ? "NO FILTER BLOCK" : "UNAVAILABLE";
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
            RestrictedAppsStatusText.Text = "No configured apps observed in the accessible process list. Unreadable processes remain unknown.";
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
            MasterBadgeText.Text = "REVIEW ONLY";
        }
        else
        {
            MasterBadge.Background = new SolidColorBrush(ColorHelper.FromArgb(255, 30, 41, 59));
            MasterBadge.BorderBrush = new SolidColorBrush(ColorHelper.FromArgb(255, 51, 65, 85));
            MasterBadgeText.Foreground = new SolidColorBrush(ColorHelper.FromArgb(255, 148, 163, 184));
            MasterBadgeText.Text = "DISABLED";
        }
    }

    private async void SaveSettingsButton_Click(object sender, RoutedEventArgs e) => await RunAsync(async () =>
    {
        if (_manager is null) return;
        if (!int.TryParse(WeekdayLimitBox.Text, out int weekday) || !int.TryParse(WeekendLimitBox.Text, out int weekend))
            throw new ArgumentException("Enter whole numbers for daily minute limits.");
        var config = new ParentalControlsConfig(MasterEnableCheckBox.IsChecked == true, ProfileNameBox.Text.Trim(),
            new(ScreenTimeEnableCheckBox.IsChecked == true, weekday, weekend, BedtimeStartBox.Text.Trim(), BedtimeEndBox.Text.Trim()),
            new(WebFilterEnableCheckBox.IsChecked == true, BlockAdultCheckBox.IsChecked == true, BlockGamblingCheckBox.IsChecked == true,
                BlockViolenceCheckBox.IsChecked == true, BlockWeaponsCheckBox.IsChecked == true, BlockDrugsCheckBox.IsChecked == true,
                Lines(CustomDomainsBox.Text), false),
            new(AppRestrictionEnableCheckBox.IsChecked == true, Lines(ConfiguredAppsBox.Text), string.Empty));
        await Task.Run(() => _manager.SaveConfig(config));
        if (!_active) return;
        UpdateMasterBadge(config.Enabled);
        AppendLog("Saved", "Policy saved locally. Saving does not enable system enforcement.", "Info");
        await RefreshPosture();
    });

    private static string[] Lines(string value) => value.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private async void ExportReportButton_Click(object sender, RoutedEventArgs e) => await RunAsync(async () =>
    {
        if (_manager is null) return;
        await RefreshPosture();
        if (!_active || _currentSnapshot is null) return;
        var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = $"Downpour-Family-Review-{DateTime.Now:yyyyMMdd-HHmmss}" };
        picker.FileTypeChoices.Add("Markdown report", new List<string> { ".md" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
        var file = await picker.PickSaveFileAsync();
        if (file is null) { AppendLog("Export", "Export cancelled.", "Info"); return; }
        var report = _manager.GenerateParentalPostureReport(_currentSnapshot, _activityLogs.ToArray());
        await Windows.Storage.FileIO.WriteTextAsync(file, report);
        AppendLog("Export", "Report saved to your selected destination.", "Info");
    });

    private void MasterEnableCheckBox_Checked(object sender, RoutedEventArgs e)
    {
        UpdateMasterBadge(true);
    }

    private void MasterEnableCheckBox_Unchecked(object sender, RoutedEventArgs e)
    {
        UpdateMasterBadge(false);
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

        if (_activityLogs.Count > 100) _activityLogs.RemoveAt(0);
        LogTextBox.Text = string.Join(Environment.NewLine, _activityLogs.AsEnumerable().Reverse()
            .Select(log => $"[{log.TimestampUtc:HH:mm:ss} UTC] {log.Severity}: {log.Category} — {log.Summary}"));
    }
}
