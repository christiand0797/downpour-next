using System.Globalization;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

/// <summary>
/// Anti-stalker view (DN-030): what can watch or control this PC right now, the local watch log of start/stop
/// transitions, the remote-control and monitoring software found, and Windows' own per-app usage records.
/// </summary>
public sealed partial class AntiStalkerPage : Page
{
    private readonly AntiStalkerClient _client = new();
    private readonly DispatcherQueueTimer _timer;
    private bool _busy;

    public AntiStalkerPage()
    {
        InitializeComponent();
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.IsRepeating = true;
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _timer.Start();
        _ = RefreshAsync(ensureService: true);
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        _timer.Stop();
        base.OnNavigatedFrom(e);
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync(bool ensureService = false)
    {
        if (_busy) return;
        _busy = true;
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null && ensureService)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }
            if (snapshot is null)
            {
                SummaryHeadline.Text = "The sensor service is not reachable";
                SummaryDetail.Text = "Anti-stalker checks run in the local sensor service. They will resume when it reconnects.";
                SetSummaryTone(warning: true);
                return;
            }
            Render(snapshot);
        }
        finally
        {
            _busy = false;
        }
    }

    private void Render(AntiStalkerSnapshot s)
    {
        var inUse = s.SensorUsage.Where(u => u.InUse).ToArray();
        var cameraNow = inUse.Where(u => u.Capability == WatchCapabilities.Camera).ToArray();
        var micNow = inUse.Where(u => u.Capability == WatchCapabilities.Microphone).ToArray();
        var screenNow = inUse.Where(u => u.Capability is WatchCapabilities.ScreenCapture or WatchCapabilities.BorderlessScreenCapture).ToArray();
        var locationNow = inUse.Where(u => u.Capability == WatchCapabilities.Location).ToArray();
        var sessions = s.RemoteSessions.Where(r => r.State == "Active").ToArray();
        var serious = s.Monitoring.Where(m => m.Severity is "HIGH" or "CRITICAL").ToArray();

        var concerns = new List<string>();
        if (sessions.Length > 0) concerns.Add($"{sessions.Length} remote session(s) controlling this PC");
        if (s.RemoteControl.Count > 0) concerns.Add($"remote-control software running ({string.Join(", ", s.RemoteControl.Select(r => r.Product).Distinct())})");
        if (serious.Length > 0) concerns.Add($"spyware or keylogger found ({string.Join(", ", serious.Select(m => m.Product).Distinct())})");
        if (screenNow.Length > 0) concerns.Add($"screen being captured by {Names(screenNow)}");
        if (cameraNow.Length > 0) concerns.Add($"camera in use by {Names(cameraNow)}");
        if (micNow.Length > 0) concerns.Add($"microphone in use by {Names(micNow)}");

        SummaryHeadline.Text = concerns.Count == 0 ? "Nothing is watching or controlling this PC right now" : "Something may be watching this PC";
        SummaryDetail.Text = concerns.Count == 0
            ? $"Checked {s.CapturedAtUtc.ToLocalTime():T}. No remote sessions, remote-control or monitoring software, and no app is using the camera, microphone, or screen capture."
            : $"Checked {s.CapturedAtUtc.ToLocalTime():T}: {string.Join("; ", concerns)}. If you did not start this, see the guidance at the bottom of this page.";
        SetSummaryTone(warning: concerns.Count > 0);

        StatusGrid.Children.Clear();
        AddTile(0, 0, "Camera", cameraNow.Length > 0 ? $"In use: {Names(cameraNow)}" : "Not in use", cameraNow.Length > 0);
        AddTile(1, 0, "Microphone", micNow.Length > 0 ? $"In use: {Names(micNow)}" : "Not in use", micNow.Length > 0);
        AddTile(2, 0, "Screen capture", screenNow.Length > 0 ? $"Capturing: {Names(screenNow)}" : "No app capturing", screenNow.Length > 0);
        AddTile(0, 1, "Remote session", sessions.Length > 0
            ? string.Join("; ", sessions.Select(r => $"{r.Protocol}{(r.ClientName is { } c ? $" from {c}" : "")}{(r.ClientAddress is { } a ? $" ({a})" : "")}"))
            : "None", sessions.Length > 0);
        AddTile(1, 1, "Remote-control apps", s.RemoteControl.Count > 0 ? string.Join(", ", s.RemoteControl.Select(r => r.Product).Distinct()) : "None running", s.RemoteControl.Count > 0);
        AddTile(2, 1, "Location", locationNow.Length > 0 ? $"In use: {Names(locationNow)}" : "Not in use", false);

        LogPanel.Children.Clear();
        LogEmpty.Visibility = s.Log.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var entry in s.Log.Take(100))
            LogPanel.Children.Add(Row($"{entry.TimeUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)} · {entry.Subject}", entry.Detail, entry.Severity));

        SoftwarePanel.Children.Clear();
        var software = s.RemoteControl.Select(r => (Title: $"{r.Product} — running ({r.ProcessName}, PID {r.ProcessId})", Detail: $"{r.Category}. It can let someone view or control this PC. If you did not install or start it, end it from Remediation or Performance and uninstall it.", Severity: r.Category == "Remote access trojan" ? "CRITICAL" : "MEDIUM"))
            .Concat(s.Monitoring.Select(m => (Title: $"{m.Product} — {m.Source}", Detail: $"{m.Category}: {m.Name}. This kind of software can record your screen, keystrokes, or activity.", m.Severity)))
            .ToArray();
        SoftwareEmpty.Visibility = software.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var item in software) SoftwarePanel.Children.Add(Row(item.Title, item.Detail, item.Severity));

        UsagePanel.Children.Clear();
        foreach (var group in s.SensorUsage.GroupBy(u => WatchCapabilities.Label(u.Capability)))
        {
            UsagePanel.Children.Add(new TextBlock { Text = group.Key, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Margin = new Thickness(0, 6, 0, 0) });
            foreach (var usage in group.OrderByDescending(u => u.LastStartUtc).Take(15))
            {
                var when = usage.InUse ? "IN USE NOW" : usage.LastStartUtc is { } start ? $"last used {start.ToLocalTime():g}" : "no recorded use";
                UsagePanel.Children.Add(new TextBlock
                {
                    Text = $"{usage.DisplayName} · {when}",
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                    Foreground = usage.InUse ? new SolidColorBrush(Color.FromArgb(255, 255, 138, 128)) : (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
                });
            }
        }
        if (s.Warnings.Count > 0)
            UsagePanel.Children.Add(new TextBlock { Text = string.Join(" ", s.Warnings), FontSize = 11, TextWrapping = TextWrapping.Wrap, Foreground = (Brush)Application.Current.Resources["TextFillColorTertiaryBrush"] });
    }

    private static string Names(IEnumerable<SensorUsage> usage) => string.Join(", ", usage.Select(u => u.DisplayName).Distinct());

    private void SetSummaryTone(bool warning)
    {
        SummaryCard.Background = new SolidColorBrush(warning ? Color.FromArgb(0x60, 0x5A, 0x14, 0x14) : Color.FromArgb(0x60, 0x0B, 0x3A, 0x24));
        SummaryCard.BorderBrush = new SolidColorBrush(warning ? Color.FromArgb(0xFF, 0xFF, 0x8A, 0x80) : Color.FromArgb(0xFF, 0x60, 0xD0, 0x90));
    }

    private void AddTile(int column, int row, string title, string detail, bool alert)
    {
        var panel = new StackPanel { Spacing = 4 };
        panel.Children.Add(new TextBlock { Text = title, FontSize = 12, Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"] });
        panel.Children.Add(new TextBlock
        {
            Text = detail,
            FontSize = 14,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(alert ? Color.FromArgb(255, 255, 138, 128) : Color.FromArgb(255, 120, 230, 160)),
        });
        var border = new Border
        {
            Padding = new Thickness(14),
            CornerRadius = new CornerRadius(10),
            BorderThickness = new Thickness(1),
            BorderBrush = new SolidColorBrush(Color.FromArgb(0x57, 0x38, 0xB9, 0xD1)),
            Background = new SolidColorBrush(Color.FromArgb(0xC8, 0x08, 0x11, 0x1E)),
            Child = panel,
        };
        Grid.SetColumn(border, column);
        Grid.SetRow(border, row);
        StatusGrid.Children.Add(border);
    }

    private static Border Row(string title, string detail, string severity)
    {
        var accent = severity switch
        {
            "CRITICAL" or "HIGH" => Color.FromArgb(255, 255, 120, 110),
            "MEDIUM" => Color.FromArgb(255, 255, 170, 90),
            _ => Color.FromArgb(255, 145, 175, 194),
        };
        var panel = new StackPanel { Spacing = 2 };
        panel.Children.Add(new TextBlock { Text = title, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        panel.Children.Add(new TextBlock { Text = detail, FontSize = 12, TextWrapping = TextWrapping.Wrap, Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"] });
        return new Border
        {
            Padding = new Thickness(12, 9, 12, 9),
            CornerRadius = new CornerRadius(8),
            BorderThickness = new Thickness(3, 0, 0, 0),
            BorderBrush = new SolidColorBrush(accent),
            Background = new SolidColorBrush(Color.FromArgb(0xC8, 0x08, 0x11, 0x1E)),
            Child = panel,
        };
    }
}
