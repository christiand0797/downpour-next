using System.Runtime.InteropServices;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace Downpour_Desktop;

/// <summary>
/// Polls the local alert store and raises Windows notifications and the optional sound alarm for new HIGH/CRITICAL
/// alerts (v29 toasts and _play_alarm). Polling continues while notifications are off so that enabling them later
/// does not replay old alerts.
/// </summary>
internal sealed class AlertNotifier : IDisposable
{
    internal const string RouteArgument = "route";
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private readonly SecurityAlertClient _client = new();
    private readonly AlertNotificationPolicy _policy = new();
    private readonly DispatcherQueueTimer _timer;
    private bool _registered;
    private bool _busy;

    public event Action<string>? RouteRequested;

    /// <summary>Why notifications cannot be shown, or null when they can.</summary>
    public string? Unavailable { get; private set; }

    public AlertNotifier(DispatcherQueue dispatcher)
    {
        try
        {
            AppNotificationManager.Default.NotificationInvoked += (_, args) =>
            {
                var route = args.Arguments.TryGetValue(RouteArgument, out var value) ? value : "threats";
                dispatcher.TryEnqueue(() => RouteRequested?.Invoke(route));
            };
            AppNotificationManager.Default.Register();
            _registered = true;
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            Unavailable = "Windows notifications could not be registered for this app.";
        }

        _timer = dispatcher.CreateTimer();
        _timer.Interval = Interval;
        _timer.IsRepeating = true;
        _timer.Tick += async (_, _) => await PollAsync();
        _timer.Start();
        _ = PollAsync();
    }

    private async Task PollAsync()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null) return;
            foreach (var notification in _policy.Next(snapshot.Alerts))
            {
                if (AppPreferences.NotificationsEnabled && _registered) Show(notification);
                if (AppPreferences.SoundAlarmEnabled && AlertNotificationPolicy.ShouldSound(notification.HighestSeverity, AppPreferences.SoundAlarmIncludesHigh))
                    PlayAlarm(notification.HighestSeverity);
            }
        }
        finally
        {
            _busy = false;
        }
    }

    private void Show(AlertNotification notification)
    {
        try
        {
            var toast = new AppNotificationBuilder()
                .AddArgument(RouteArgument, "threats")
                .AddText(notification.Title)
                .AddText(notification.Body)
                .BuildNotification();
            AppNotificationManager.Default.Show(toast);
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or ArgumentException)
        {
            Unavailable = "A Windows notification could not be shown.";
        }
    }

    internal static void PlayAlarm(string severity)
    {
        var pattern = AlertNotificationPolicy.BeepPattern(severity);
        _ = Task.Run(() =>
        {
            foreach (var (frequency, duration) in pattern) Beep((uint)frequency, (uint)duration);
        });
    }

    public void Dispose()
    {
        _timer.Stop();
        if (_registered)
        {
            try { AppNotificationManager.Default.Unregister(); }
            catch (Exception exception) when (exception is COMException or InvalidOperationException) { }
            _registered = false;
        }
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Beep(uint frequency, uint duration);
}
