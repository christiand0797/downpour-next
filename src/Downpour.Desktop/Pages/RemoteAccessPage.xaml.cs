using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class RemoteAccessPage : Page
{
    private readonly RemoteAccessClient _client = new();
    private bool _busy;

    public ObservableCollection<RemoteAccessRow> Findings { get; } = [];
    public ObservableCollection<RemoteAccessRow> Exposures { get; } = [];
    public ObservableCollection<string> Tools { get; } = [];

    public RemoteAccessPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_busy) return;
        _busy = true;
        RefreshButton.IsEnabled = false;
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }
            Findings.Clear();
            Exposures.Clear();
            Tools.Clear();
            if (snapshot is null)
            {
                StatusHeadline.Text = "Downpour is running · remote-access sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted data is shown.";
                return;
            }
            App.MarkSensorServiceConnected();
            foreach (var finding in snapshot.Findings) Findings.Add(new RemoteAccessRow(finding.Severity, finding.Summary, ""));
            foreach (var exposure in snapshot.Exposures.OrderBy(exposure => Rank(exposure.Risk)))
                Exposures.Add(new RemoteAccessRow(exposure.Risk,
                    exposure.Kind == RemoteAccessKinds.Listener
                        ? $"Port {exposure.LocalPort} · {exposure.Description} · {exposure.ProcessName} (PID {exposure.ProcessId})"
                        : $"{exposure.RemoteEndpoint} from local port {exposure.LocalPort} · {exposure.Description} · {exposure.ProcessName} (PID {exposure.ProcessId})",
                    exposure.Kind));
            foreach (var tool in snapshot.Tools) Tools.Add($"{tool.ProcessName} (PID {tool.ProcessId}) · {tool.Category}");
            NoFindings.Visibility = Findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            NoExposures.Visibility = Exposures.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            NoTools.Visibility = Tools.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            var rdp = snapshot.RdpEnabled switch
            {
                true => $"Remote Desktop is ON (port {snapshot.RdpPort?.ToString() ?? "unknown"}, NLA {(snapshot.RdpNetworkLevelAuthentication switch { true => "required", false => "OFF", null => "unknown" })})",
                false => "Remote Desktop is off",
                null => "Remote Desktop state unknown"
            };
            StatusHeadline.Text = $"{rdp} · {snapshot.Exposures.Count} remote-access port{(snapshot.Exposures.Count == 1 ? "" : "s")} · {snapshot.Tools.Count} tool{(snapshot.Tools.Count == 1 ? "" : "s")} running";
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"Scanned {snapshot.CapturedAtUtc.ToLocalTime():HH:mm:ss}. Process names only; no command lines are collected.{warnings}";
        }
        finally
        {
            _busy = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private static int Rank(string risk) => risk switch { "Critical" => 0, "High" => 1, "Medium" => 2, _ => 3 };
}

public sealed class RemoteAccessRow(string severity, string text, string kind)
{
    public string Severity => severity.ToUpperInvariant();
    public string Risk => severity;
    public string Text => text;
    public string Kind => kind;
    public SolidColorBrush Brush => new(severity.ToUpperInvariant() switch
    {
        "CRITICAL" or "HIGH" => Color.FromArgb(255, 255, 120, 110),
        "MEDIUM" => Color.FromArgb(255, 255, 170, 90),
        _ => Color.FromArgb(255, 255, 214, 102)
    });
}
