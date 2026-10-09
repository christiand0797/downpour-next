using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class SettingsPage : Page
{
    private readonly Downpour.Core.SensorSettingsClient _sensorSettings = new();
    private readonly Downpour.Core.IntelClient _intel = new();

    public System.Collections.ObjectModel.ObservableCollection<string> IntelResults { get; } = [];
    public System.Collections.ObjectModel.ObservableCollection<string> IntelLog { get; } = [];
    private bool _loading;

    public SettingsPage()
    {
        InitializeComponent();

        // Attach handlers only after every named control has been materialized.
        // ToggleSwitch can raise Toggled while its initial state is applied; wiring
        // handlers in XAML can run them before the page's generated fields are ready.
        RainEffectsToggle.Toggled += RainEffects_Toggled;
        ReduceMotionToggle.Toggled += ReduceMotion_Toggled;
        AutoStormToggle.Toggled += AutoStorm_Toggled;
        NotificationsToggle.Toggled += (_, _) => Save(() => AppPreferences.NotificationsEnabled = NotificationsToggle.IsOn);
        MinimizeToTrayToggle.Toggled += (_, _) => Save(() => AppPreferences.MinimizeToTray = MinimizeToTrayToggle.IsOn);
        SoundAlarmToggle.Toggled += (_, _) => Save(() => AppPreferences.SoundAlarmEnabled = SoundAlarmToggle.IsOn);
        SoundHighToggle.Toggled += (_, _) => Save(() => AppPreferences.SoundAlarmIncludesHigh = SoundHighToggle.IsOn);
        RansomwareSamplingToggle.Toggled += (_, _) => Save(() => AppPreferences.RansomwareContentSampling = RansomwareSamplingToggle.IsOn);
        ScriptBlockToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.ScriptBlockAnalysis, ScriptBlockToggle.IsOn);
        IntelLookupsToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.IntelLookups, IntelLookupsToggle.IsOn);
        QuarantineActionsToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.QuarantineActions, QuarantineActionsToggle.IsOn);
        ProcessActionsToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.ProcessTerminationActions, ProcessActionsToggle.IsOn);
        FirewallActionsToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.FirewallActions, FirewallActionsToggle.IsOn);
        UsbActionsToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.UsbActions, UsbActionsToggle.IsOn);
        HostIsolationToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.HostIsolationActions, HostIsolationToggle.IsOn);
        ThreatDatabasesToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.ThreatDatabases, ThreatDatabasesToggle.IsOn);
    }

    private async Task LoadSensorSettingsAsync()
    {
        var response = await _sensorSettings.GetAsync();
        if (response?.Settings is null)
        {
            await App.EnsureSensorServiceAsync();
            response = await _sensorSettings.GetAsync();
        }
        _loading = true;
        try
        {
            if (response?.Settings is { } settings)
            {
                ScriptBlockToggle.IsOn = settings.ScriptBlockAnalysis;
                ScriptBlockToggle.IsEnabled = true;
                IntelLookupsToggle.IsOn = settings.IntelLookups;
                IntelLookupsToggle.IsEnabled = true;
                QuarantineActionsToggle.IsOn = settings.QuarantineActions;
                QuarantineActionsToggle.IsEnabled = true;
                ProcessActionsToggle.IsOn = settings.ProcessTerminationActions;
                ProcessActionsToggle.IsEnabled = true;
                FirewallActionsToggle.IsOn = settings.FirewallActions;
                FirewallActionsToggle.IsEnabled = true;
                UsbActionsToggle.IsOn = settings.UsbActions;
                UsbActionsToggle.IsEnabled = true;
                HostIsolationToggle.IsOn = settings.HostIsolationActions;
                HostIsolationToggle.IsEnabled = true;
                ThreatDatabasesToggle.IsOn = settings.ThreatDatabases;
                ThreatDatabasesToggle.IsEnabled = true;
                ShowConfiguredKeys(settings.IntelServicesConfigured ?? []);
                SensorSettingsState.Text = "";
            }
            else
            {
                ScriptBlockToggle.IsEnabled = false;
                IntelLookupsToggle.IsEnabled = false;
                QuarantineActionsToggle.IsEnabled = false;
                ProcessActionsToggle.IsEnabled = false;
                FirewallActionsToggle.IsEnabled = false;
                UsbActionsToggle.IsEnabled = false;
                HostIsolationToggle.IsEnabled = false;
                ThreatDatabasesToggle.IsEnabled = false;
                SensorSettingsState.Text = "The sensor service is not reachable, so its settings cannot be shown or changed.";
            }
        }
        finally
        {
            _loading = false;
        }
    }

    private (PasswordBox Box, TextBlock State)? KeyControls(string service) => service switch
    {
        Downpour.Contracts.IntelServices.VirusTotal => (VirusTotalKeyBox, VirusTotalKeyState),
        Downpour.Contracts.IntelServices.AbuseIpDb => (AbuseIpDbKeyBox, AbuseIpDbKeyState),
        Downpour.Contracts.IntelServices.GreyNoise => (GreyNoiseKeyBox, GreyNoiseKeyState),
        _ => null
    };

    private void ShowConfiguredKeys(IReadOnlyList<string> configured)
    {
        foreach (var service in Downpour.Contracts.IntelServices.All)
            if (KeyControls(service) is { } controls)
                controls.State.Text = configured.Contains(service) ? "Configured" : "Not configured";
    }

    private async void SaveIntelKey_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string service } || KeyControls(service) is not { } controls) return;
        var key = controls.Box.Password.Trim();
        controls.Box.Password = "";
        if (key.Length == 0) { controls.State.Text = "Paste a key first"; return; }
        var response = await _sensorSettings.SetApiKeyAsync(service, key);
        controls.State.Text = response is { Accepted: true } ? "Configured" : "Not saved";
        if (response?.Settings is { } settings) ShowConfiguredKeys(settings.IntelServicesConfigured ?? []);
    }

    private async void RemoveIntelKey_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string service } || KeyControls(service) is not { } controls) return;
        var response = await _sensorSettings.ClearApiKeyAsync(service);
        if (response?.Settings is { } settings) ShowConfiguredKeys(settings.IntelServicesConfigured ?? []);
        else controls.State.Text = "Not removed";
    }

    private async Task LoadIntelStatusAsync()
    {
        var snapshot = await _intel.TryGetSnapshotAsync();
        IntelResults.Clear();
        IntelLog.Clear();
        if (snapshot is null)
        {
            IntelRunState.Text = "Intel lookup status is unavailable while the sensor service is offline.";
            return;
        }
        IntelRunState.Text = snapshot.LastRunUtc is { } last
            ? $"Last run {last.ToLocalTime():MM-dd HH:mm}: {snapshot.LastRunStatus}"
            : snapshot.LastRunStatus;
        foreach (var result in snapshot.Results.Where(r => r.Verdict != Downpour.Contracts.IntelVerdicts.Clean).Take(20))
            IntelResults.Add($"{result.Verdict} · {result.Indicator} · {result.Service}: {result.Summary}");
        if (IntelResults.Count == 0) IntelResults.Add(snapshot.Results.Count == 0 ? "No results yet." : $"{snapshot.Results.Count} indicators checked; none flagged.");
        foreach (var record in snapshot.RecentLookups.Take(15))
            IntelLog.Add($"{record.SentAtUtc.ToLocalTime():MM-dd HH:mm:ss}  {record.Service,-10} {record.IndicatorKind,-6} {record.Outcome}");
        if (IntelLog.Count == 0) IntelLog.Add("Nothing has been sent.");
    }

    private async Task SetSensorSettingAsync(string key, bool value)
    {
        if (_loading) return;
        var response = await _sensorSettings.SetAsync(key, value);
        SensorSettingsState.Text = response is { Accepted: true } ? "Saved by the sensor service." : "The sensor service did not save the change.";
        if (response is not { Accepted: true }) await LoadSensorSettingsAsync();
    }

    private void Save(Action apply)
    {
        if (!_loading) apply();
        SoundHighToggle.IsEnabled = SoundAlarmToggle.IsOn;
        ShowSaveState();
    }

    private void TestAlarm_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        AlertNotifier.PlayAlarm(AppPreferences.SoundAlarmIncludesHigh ? "HIGH" : "CRITICAL");

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshCacheAsync();
        _loading = true;
        try
        {
            RainEffectsToggle.IsOn = AppPreferences.RainEffectsEnabled;
            ReduceMotionToggle.IsOn = AppPreferences.ReduceMotion;
            AutoStormToggle.IsOn = AppPreferences.AutoStormCycle;
            NotificationsToggle.IsOn = AppPreferences.NotificationsEnabled;
            MinimizeToTrayToggle.IsOn = AppPreferences.MinimizeToTray;
            SoundAlarmToggle.IsOn = AppPreferences.SoundAlarmEnabled;
            SoundHighToggle.IsOn = AppPreferences.SoundAlarmIncludesHigh;
            RansomwareSamplingToggle.IsOn = AppPreferences.RansomwareContentSampling;
            SoundHighToggle.IsEnabled = SoundAlarmToggle.IsOn;
            NotificationState.Text = App.NotificationsUnavailable ?? "";
            _ = LoadSensorSettingsAsync();
            _ = LoadIntelStatusAsync();
        }
        finally
        {
            _loading = false;
        }
        ShowSaveState();
    }

    private void RainEffects_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (!_loading) AppPreferences.RainEffectsEnabled = RainEffectsToggle.IsOn;
        ShowSaveState();
    }

    private void ReduceMotion_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (!_loading) AppPreferences.ReduceMotion = ReduceMotionToggle.IsOn;
        ShowSaveState();
    }

    private void AutoStorm_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (!_loading)
        {
            AppPreferences.AutoStormCycle = AutoStormToggle.IsOn;
            StormModeController.SetAutomaticCycling(AppPreferences.AutoStormCycle);
        }
        ShowSaveState();
    }

    private void ShowSaveState() => SaveState.Text = AppPreferences.PersistenceAvailable
        ? "Preferences are saved locally for this Windows user."
        : "Local preference storage is unavailable; current choices last only until the app closes.";
}
