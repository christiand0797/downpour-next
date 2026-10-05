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

    internal static IntPtr MainWindowHandle =>
        Current is App app && app._window is not null
            ? WinRT.Interop.WindowNative.GetWindowHandle(app._window)
            : IntPtr.Zero;

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
        _window.Closed += (_, _) => sensorService.Dispose();
        _window.Activate();
        _ = _sensorService.EnsureRunningAsync();
    }
}
