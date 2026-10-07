using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Downpour_Desktop;

/// <summary>
/// Provides application-specific behavior to supplement the default Application class.
/// </summary>
public partial class App : Application
{
    private Window? _window;
    private SensorServiceProcess? _sensorService;
    private TrayIcon? _tray;
    private AlertNotifier? _notifier;
    private MinimizeWatcher? _minimizeWatcher;

    internal static string? NotificationsUnavailable => Current is App app ? app._notifier?.Unavailable : null;

    internal static string SensorServiceStatusHint { get; private set; } =
        "The desktop app is running; sensor-service startup has not completed.";

    internal static Task EnsureSensorServiceAsync() =>
        Current is App app && app._sensorService is not null
            ? app._sensorService.EnsureRunningAsync()
            : Task.CompletedTask;

    internal static void CloseMainWindow()
    {
        if (Current is App app) app._window?.Close();
    }

    internal static void NavigateToRoute(string routeId)
    {
        if (Current is App app && app._window is MainWindow mainWindow)
        {
            mainWindow.ShowRoute(routeId);
        }
    }

    internal static IntPtr MainWindowHandle =>
        Current is App app && app._window is not null
            ? WinRT.Interop.WindowNative.GetWindowHandle(app._window)
            : IntPtr.Zero;

    private void HideToTrayIfMinimized()
    {
        if (_window is null || !AppPreferences.MinimizeToTray || _tray?.IsVisible != true || !_window.AppWindow.IsVisible) return;
        if (_window.AppWindow.Presenter is Microsoft.UI.Windowing.OverlappedPresenter { State: Microsoft.UI.Windowing.OverlappedPresenterState.Minimized })
            _window.AppWindow.Hide();
    }

    private void RestoreMainWindow()
    {
        if (_window is null) return;
        _window.AppWindow.Show();
        if (_window.AppWindow.Presenter is Microsoft.UI.Windowing.OverlappedPresenter { State: Microsoft.UI.Windowing.OverlappedPresenterState.Minimized } presenter)
            presenter.Restore();
        _window.Activate();
    }

    internal static void MarkSensorServiceConnected() =>
        SensorServiceStatusHint = "The desktop app is running and connected to the local sensor service.";
    
    /// <summary>
    /// Initializes the singleton application object.  This is the first line of authored code
    /// executed, and as such is the logical equivalent of main() or WinMain().
    /// </summary>
    public App()
    {
        InitializeComponent();
        AppPreferences.Load();
    }

    /// <summary>
    /// Invoked when the application is launched.
    /// </summary>
    /// <param name="args">Details about the launch request and process.</param>
    protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
    {
        _window = new MainWindow();
        var sensorService = new SensorServiceProcess(message => SensorServiceStatusHint = message);
        _sensorService = sensorService;
        _window.Closed += (_, _) =>
        {
            _notifier?.Dispose();
            _tray?.Dispose();
            sensorService.Dispose();
        };

        var dispatcher = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
        _tray = new TrayIcon(System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico"), "Downpour Next");
        _tray.ShowRequested += RestoreMainWindow;
        _tray.ExitRequested += () => _window?.Close();
        _notifier = new AlertNotifier(dispatcher);
        _notifier.RouteRequested += route =>
        {
            RestoreMainWindow();
            (_window as MainWindow)?.ShowRoute(route);
        };
        // v29 _on_minimize: a minimized window is withdrawn to the tray when minimize_to_tray is on (default).
        // AppWindow.Changed does not fire for a plain minimize, so watch WM_SIZE / SIZE_MINIMIZED instead.
        _minimizeWatcher = new MinimizeWatcher(MainWindowHandle, () => dispatcher.TryEnqueue(HideToTrayIfMinimized));
        _window.Closed += (_, _) => _minimizeWatcher?.Dispose();
        _window.Activate();
        _ = _sensorService.EnsureRunningAsync();
    }
}
