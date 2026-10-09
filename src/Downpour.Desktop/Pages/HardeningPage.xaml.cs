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

    private readonly BreakdownChart _stateChart = new() { Title = "Hardening checks", Subtitle = "Passed, needs attention, or not readable without administrator rights" };
    private readonly BreakdownChart _severityChart = new() { Title = "Findings by severity", Subtitle = "Checks that need attention" };
    private readonly TopBarsChart _categoryChart = new() { Title = "Findings by area", Subtitle = "Where the hardening gaps are" };
    private IReadOnlyList<PostureCheck> _all = [];

    public HardeningPage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _stateChart, _severityChart, _categoryChart);
        UpdateUndo();
        EntityDetails.Attach(CheckList, item => item is PostureRow p ? new DetailEntity(p.Title, $"{p.Category} · {p.StateLabel}",
        [
            new("State", p.StateLabel), new("Area", p.Category), new("Reading", p.Detail), new("How to fix", p.Check.Fix ?? "Nothing to do."),
            new("MITRE technique", p.Technique), new("Check ID", p.Check.Id),
        ], Kind: "hardening check") : null);
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

            if (snapshot is null)
            {
                StatusHeadline.Text = "Downpour is running · hardening sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} No cached or substituted posture is shown.";
                Checks.Clear();
                EmptyState.Visibility = Visibility.Visible;
                return;
            }

            App.MarkSensorServiceConnected();
            _all = snapshot.Checks;
            ApplyFilter();

            var findings = snapshot.Checks.Count(check => check.State == PostureStates.Finding);
            var unknown = snapshot.Checks.Count(check => check.State == PostureStates.Unknown);
            var passed = snapshot.Checks.Count - findings - unknown;
            var score = Score(snapshot.Checks);
            StatusHeadline.Text = (findings == 0
                ? $"Hardening score {score}/100 · no findings · {passed} passed · {unknown} unknown"
                : $"Hardening score {score}/100 · {findings} finding{(findings == 1 ? "" : "s")} · {passed} passed · {unknown} unknown");
            _categoryChart.SetData(snapshot.Checks.Where(c => c.State == PostureStates.Finding)
                .GroupBy(c => c.Category ?? "Other").Select(g => (g.Key, (double)g.Count())), "", HudPalette.Categorical[2]);
            _stateChart.SetData([("Passed", passed), ("Needs attention", findings), ("Unknown", unknown)],
                new Dictionary<string, Windows.UI.Color> { ["Passed"] = HudPalette.Good, ["Needs attention"] = HudPalette.Serious, ["Unknown"] = HudPalette.Other });
            _severityChart.SetData(snapshot.Checks.Where(c => c.State == PostureStates.Finding).GroupBy(c => c.Severity, StringComparer.OrdinalIgnoreCase).Select(g => (g.Key, (double)g.Count())));
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

    /// <summary>100 minus a severity-weighted penalty per finding; Unknown checks are not counted either way.</summary>
    public static int Score(IReadOnlyList<PostureCheck> checks) => Math.Clamp(100 - checks.Where(c => c.State == PostureStates.Finding)
        .Sum(c => c.Severity switch { "CRITICAL" => 25, "HIGH" => 12, "MEDIUM" => 6, "LOW" => 2, _ => 0 }), 0, 100);

    private void ViewFilter_SelectionChanged(object sender, SelectionChangedEventArgs e) => ApplyFilter();

    private bool _fixing;

    private async void FixOne_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not string id || HardeningFixes.Find(id) is not { } fix) return;
        if (fix.Caution is { } caution && !await ActionFlows.ConfirmAsync(XamlRoot, fix.Title, $"{fix.WhatChanges}{Environment.NewLine}{Environment.NewLine}Heads up: {caution}{Environment.NewLine}{Environment.NewLine}The previous setting is backed up and Undo restores it.", "Apply fix"))
            return;
        await RunFixesAsync([id]);
    }

    private async void FixAll_Click(object sender, RoutedEventArgs e)
    {
        var fixes = _all.Where(c => c.State == PostureStates.Finding).Select(c => HardeningFixes.Find(c.Id)).OfType<HardeningFix>().Where(f => f.Caution is null).ToArray();
        if (fixes.Length == 0)
        {
            ShowFixResult("Nothing to fix automatically: the remaining findings have side effects, so apply them one at a time with their Fix button.");
            return;
        }
        if (!await ActionFlows.ConfirmAsync(XamlRoot, $"Apply {fixes.Length} fix{(fixes.Length == 1 ? "" : "es")}?",
                string.Join(Environment.NewLine, fixes.Select(f => "• " + f.Title)) + $"{Environment.NewLine}{Environment.NewLine}Windows will ask for permission once. Every setting is backed up first and Undo puts it back.", "Fix all"))
            return;
        await RunFixesAsync(fixes.Select(f => f.Id).ToArray());
    }

    private async Task RunFixesAsync(IReadOnlyList<string> ids)
    {
        if (_fixing) return;
        _fixing = true;
        FixAllButton.IsEnabled = false;
        ShowFixResult($"Applying {ids.Count} fix{(ids.Count == 1 ? "" : "es")}… approve the Windows permission prompt.");
        try
        {
            var result = await FixerClient.ApplyAsync(ids);
            ShowFixResult(FixerClient.Describe(result));
            await RefreshAsync();
        }
        finally
        {
            _fixing = false;
            FixAllButton.IsEnabled = true;
            UpdateUndo();
        }
    }

    private async void Undo_Click(object sender, RoutedEventArgs e)
    {
        if (FixerProtocol.RecentBackups(1).FirstOrDefault() is not { } backup) return;
        var titles = backup.FixIds.Select(id => HardeningFixes.Find(id)?.Title ?? id);
        if (!await ActionFlows.ConfirmAsync(XamlRoot, "Undo the last fixes?", $"From {backup.CreatedUtc.ToLocalTime():MMM d HH:mm}:{Environment.NewLine}{string.Join(Environment.NewLine, titles.Select(t => "• " + t))}", "Undo"))
            return;
        ShowFixResult("Undoing… approve the Windows permission prompt.");
        var result = await FixerClient.UndoAsync(backup.BackupId);
        ShowFixResult(FixerClient.Describe(result));
        UpdateUndo();
        await RefreshAsync();
    }

    private async void InstallUpdates_Click(object sender, RoutedEventArgs e)
    {
        var result = await UpdateRunner.RunAsync(XamlRoot, "software", ShowFixResult);
        if (result is not null) await RefreshAsync();
    }

    private void UpdateUndo()
    {
        var last = FixerProtocol.RecentBackups(1).FirstOrDefault();
        UndoButton.IsEnabled = last is not null;
        ToolTipService.SetToolTip(UndoButton, last is null ? "No fixes to undo" : $"Undo {last.FixIds.Count} fix(es) from {last.CreatedUtc.ToLocalTime():MMM d HH:mm}");
    }

    private void ShowFixResult(string text)
    {
        FixResultText.Text = text;
        FixResultPanel.Visibility = Visibility.Visible;
    }

    private void ApplyFilter()
    {
        if (CheckList is null) return;
        var view = ViewFilter?.SelectedIndex ?? 0;
        Checks.Clear();
        foreach (var check in _all
            .Where(c => view switch { 1 => c.State != PostureStates.Pass, 2 => c.State == PostureStates.Pass, _ => true })
            .OrderBy(check => check.State switch { PostureStates.Finding => 0, PostureStates.Unknown => 1, _ => 2 })
            .ThenBy(check => SeverityRank(check.Severity)).ThenBy(check => check.Category))
            Checks.Add(new PostureRow(check));
        EmptyState.Visibility = Checks.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void OpenSetting_Click(object sender, RoutedEventArgs e)
    {
        // Only the fixed Windows Security and Settings links from HardeningGuidance are ever opened.
        if ((sender as FrameworkElement)?.Tag is not string uri || !HardeningGuidance.AllowedUris.Contains(uri)) return;
        try { await Windows.System.Launcher.LaunchUriAsync(new Uri(uri)); }
        catch (Exception ex) when (ex is UriFormatException or InvalidOperationException or System.Runtime.InteropServices.COMException) { }
    }

    private void CopyFixes_Click(object sender, RoutedEventArgs e)
    {
        var text = new System.Text.StringBuilder($"Downpour hardening fix list · score {Score(_all)}/100 · {DateTime.Now:yyyy-MM-dd HH:mm}{Environment.NewLine}");
        foreach (var check in _all.Where(c => c.State != PostureStates.Pass).OrderBy(c => SeverityRank(c.Severity)))
            text.AppendLine().AppendLine($"[{(check.State == PostureStates.Finding ? check.Severity : "UNKNOWN")}] {check.Title} ({check.Category})")
                .AppendLine($"  {check.Detail}").AppendLine($"  Fix: {check.Fix ?? "-"}");
        EntityDetails.Copy(text.ToString());
    }

    private static int SeverityRank(string severity) => severity switch
    {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4
    };
}

public sealed class PostureRow(PostureCheck check)
{
    public PostureCheck Check => check;
    public string Category => (check.Category ?? "").ToUpperInvariant();
    public string FixText => check.Fix is null ? "" : $"How to fix: {check.Fix}";
    public Visibility FixVisibility => check.Fix is null ? Visibility.Collapsed : Visibility.Visible;
    public string? SettingsUri => check.SettingsUri;
    private HardeningFix? AutoFix => check.State == PostureStates.Pass ? null : HardeningFixes.Find(check.Id);
    public Visibility AutoFixVisibility => AutoFix is null ? Visibility.Collapsed : Visibility.Visible;
    public string AutoFixLabel => AutoFix?.Caution is null ? "Fix" : "Fix…";
    public string AutoFixTip => AutoFix is { } f ? f.WhatChanges + (f.RebootRequired ? " Needs a restart." : "") + (f.Caution is { } c ? $" Note: {c}" : "") : "";
    /// <summary>Windows' own page only when Downpour cannot apply the fix itself (firmware, BitLocker, tamper protection).</summary>
    private bool IsUpdates => check.State != PostureStates.Pass && check.Id is "update-age" or "os-support";
    public Visibility UpdatesVisibility => IsUpdates ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OpenVisibility => check.SettingsUri is null || AutoFix is not null || IsUpdates ? Visibility.Collapsed : Visibility.Visible;
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
