using System.Collections.ObjectModel;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class HardeningPage : Page
{
    private readonly HardeningPostureClient _client = new();
    private bool _requestInFlight;

    public LiveCollection<PostureRow> Checks { get; } = [];

    public HardeningPage()
    {
        InitializeComponent();
        LiveRefresh.Attach(this, () => RefreshAsync(quiet: true));
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync(bool quiet = false)
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        if (!quiet) RefreshButton.IsEnabled = false;
        if (!quiet) StatusHeadline.Text = "Checking platform posture";
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            Checks.Clear();
            if (snapshot is null)
            {
                StatusHeadline.Text = "Downpour is running · hardening sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted posture is shown.";
                EmptyState.Visibility = Visibility.Visible;
                return;
            }

            App.MarkSensorServiceConnected();
            foreach (var check in snapshot.Checks
                .OrderBy(check => check.State switch { PostureStates.Finding => 0, PostureStates.Unknown => 1, _ => 2 })
                .ThenBy(check => SeverityRank(check.Severity)))
                Checks.Add(new PostureRow(check));
            EmptyState.Visibility = Checks.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            var findings = snapshot.Checks.Count(check => check.State == PostureStates.Finding);
            var unknown = snapshot.Checks.Count(check => check.State == PostureStates.Unknown);
            var passed = snapshot.Checks.Count - findings - unknown;
            StatusHeadline.Text = findings == 0
                ? $"No posture findings · {passed} passed · {unknown} unknown"
                : $"{findings} posture finding{(findings == 1 ? "" : "s")} · {passed} passed · {unknown} unknown";
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var elevation = snapshot.IsElevated ? "Sensor is elevated." : "Sensor is not elevated, so BitLocker and TPM readiness may be Unknown.";
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"Checked {captured:HH:mm:ss}. {elevation}{warnings}";
        }
        finally
        {
            _requestInFlight = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4
    };
}

public sealed class PostureRow(PostureCheck check)
{
    public string Title => check.Title;
    public string Detail => check.Detail;
    public string Technique => check.Technique;
    public string StateLabel => check.State == PostureStates.Finding ? check.Severity : check.State.ToUpperInvariant();

    public SolidColorBrush StateForeground => new(check.State switch
    {
        PostureStates.Pass => Color.FromArgb(255, 120, 230, 160),
        PostureStates.Unknown => Color.FromArgb(255, 255, 214, 102),
        _ => check.Severity == "HIGH" || check.Severity == "CRITICAL"
            ? Color.FromArgb(255, 255, 120, 110)
            : Color.FromArgb(255, 255, 170, 90)
    });

    public SolidColorBrush StateBackground => new(check.State switch
    {
        PostureStates.Pass => Color.FromArgb(48, 60, 200, 120),
        PostureStates.Unknown => Color.FromArgb(48, 230, 190, 60),
        _ => Color.FromArgb(56, 240, 90, 70)
    });
}
