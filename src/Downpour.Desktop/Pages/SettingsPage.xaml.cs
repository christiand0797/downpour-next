using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class SettingsPage : Page
{
    private readonly Downpour.Core.SensorSettingsClient _sensorSettings = new();
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
        ScriptBlockToggle.Toggled += async (_, _) => await SetSensorSettingAsync(Downpour.Contracts.SensorSettingKeys.ScriptBlockAnalysis, ScriptBlockToggle.IsOn);
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
                SensorSettingsState.Text = "";
            }
            else
            {
                ScriptBlockToggle.IsEnabled = false;
                SensorSettingsState.Text = "The sensor service is not reachable, so its settings cannot be shown or changed.";
            }
        }
        finally
        {
            _loading = false;
        }
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
            SoundHighToggle.IsEnabled = SoundAlarmToggle.IsOn;
            NotificationState.Text = App.NotificationsUnavailable ?? "";
            _ = LoadSensorSettingsAsync();
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
