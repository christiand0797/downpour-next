using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class SettingsPage : Page
{
    private bool _loading;

    public SettingsPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _loading = true;
        RainEffectsToggle.IsOn = AppPreferences.RainEffectsEnabled;
        ReduceMotionToggle.IsOn = AppPreferences.ReduceMotion;
        AutoStormToggle.IsOn = AppPreferences.AutoStormCycle;
        _loading = false;
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
