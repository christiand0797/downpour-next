using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace Downpour_Desktop.Pages;

public sealed partial class CognitiveImmuneSystemPage : Page
{
    private readonly SecurityAlertClient _alerts = new();
    private readonly SystemSnapshotClient _system = new();
    private readonly SensorSettingsClient _settings = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private CancellationTokenSource _lifetime = new();
    private CancellationTokenSource? _integrityCancellation;
    private CisAssessment? _assessment;
    private PackageIntegrityAssessment? _integrity;
    private bool _refreshing;
    private bool _checking;
    private int _generation;

    public CognitiveImmuneSystemPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_lifetime.IsCancellationRequested) { _lifetime.Dispose(); _lifetime = new(); }
        _generation++;
        _timer.Start();
        await RefreshAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _generation++;
        _timer.Stop();
        _lifetime.Cancel();
        _integrityCancellation?.Cancel();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_refreshing || _lifetime.IsCancellationRequested) return;
        _refreshing = true;
        var generation = _generation;
        var token = _lifetime.Token;
        try
        {
            await App.EnsureSensorServiceAsync();
            token.ThrowIfCancellationRequested();
            var alerts = _alerts.TryGetSnapshotAsync(token);
            var system = _system.TryGetSnapshotAsync(token);
            var settings = _settings.GetAsync(token);
            await Task.WhenAll(alerts, system, settings);
            var response = await settings;
            var assessment = await Task.Run(() => CognitiveImmuneSystemCoordinator.Assess(alerts.Result, system.Result,
                response is { Accepted: true } ? response.Settings : null), token);
            if (generation != _generation || token.IsCancellationRequested) return;
            _assessment = assessment;
            AssessmentStatus.Text = $"{assessment.Status} · checked {assessment.CapturedAtUtc:u} · live, updates every second";
            WindowScope.Text = $"Returned {Count(assessment.ReviewedAlerts)} of {Count(assessment.StoredAlerts)} stored alerts. Alert snapshot: {assessment.AlertCapturedAtUtc?.ToString("u") ?? "unavailable"}.";
            MeasuredCounts.Text = $"Open: {Count(assessment.OpenAlerts)} · Urgent open: {Count(assessment.UrgentOpenAlerts)} · User-verified active: {Count(assessment.VerifiedActiveAlerts)}";
            TechniqueCounts.Text = $"Suppressed: {Count(assessment.SuppressedAlerts)} · Observed techniques: {Count(assessment.ObservedTechniques)}";
            LiveList.Set(SourceList, assessment.Sources.Select(s => $"{s.Name} — {s.Status}: {s.Detail}").ToArray());
            LiveList.Set(WarningList, assessment.Warnings.Count == 0 ? new[] { "No warnings in the returned measurements. This is not a complete protection verdict." } : assessment.Warnings);
            LiveList.Set(RecentAlertList, assessment.RecentAlerts.Count == 0 ? new[] { assessment.ReviewedAlerts is null ? "Alerts unavailable." : "No alerts in the returned window." } :
                assessment.RecentAlerts.Select(a => $"{a.LastSeenUtc:u} · {a.Severity} · {a.State} · {a.Technique} · {a.Title}").ToArray());
            LiveList.Set(CorrelationList, assessment.Correlations.Count == 0 ? new[] { "No supported temporal pairs in the returned window." } :
                assessment.Correlations.Select(c => $"{c.Title}: {c.EvidenceSummary} {c.Limitation}").ToArray());
            CopyReportButton.IsEnabled = true;
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (generation == _generation)
            {
                _assessment = null;
                CopyReportButton.IsEnabled = false;
                AssessmentStatus.Text = "Measurements unavailable";
                WindowScope.Text = "Refresh failed. Previously rendered rows are historical; current counts are unknown.";
                MeasuredCounts.Text = "Open: unknown · Urgent open: unknown · User-verified active: unknown";
                TechniqueCounts.Text = "Suppressed: unknown · Observed techniques: unknown";
                LiveList.Set(SourceList, null);
                LiveList.Set(WarningList, new[] { "Refresh failed; absence of data is not absence of threats." });
                LiveList.Set(RecentAlertList, null);
                LiveList.Set(CorrelationList, null);
                Notify(InfoBarSeverity.Error, "Refresh failed", ex.GetType().Name);
            }
        }
        finally { _refreshing = false; }
    }

    private async void Integrity_Click(object sender, RoutedEventArgs e)
    {
        if (_checking) return;
        _checking = true;
        IntegrityButton.IsEnabled = false;
        CancelIntegrityButton.IsEnabled = true;
        _integrityCancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        var token = _integrityCancellation.Token;
        var generation = _generation;
        IntegrityStatus.Text = "Checking package files…";
        _integrity = null;
        LiveList.Set(IntegrityFindings, null);
        var progress = new Progress<string>(message => { if (generation == _generation && !token.IsCancellationRequested) IntegrityProgress.Text = message; });
        try
        {
            var version = typeof(CognitiveImmuneSystemPage).Assembly.GetName().Version!.ToString(3);
            var result = await Task.Run(() => PackageIntegrityInspector.InspectAsync(AppContext.BaseDirectory, version, progress, token), token);
            if (generation != _generation || token.IsCancellationRequested) return;
            _integrity = result;
            IntegrityStatus.Text = $"{result.Status} · {result.MatchingFiles}/{result.ExpectedFiles} match · {result.CheckedFiles} checked · {result.BytesHashed:N0} bytes hashed";
            IntegrityProgress.Text = $"Checked {result.CapturedAtUtc:u}. Manifest SHA-256: {result.ManifestSha256 ?? "unavailable"}.";
            LiveList.Set(IntegrityFindings, result.Findings.Take(128).Select(f => $"{f.RelativePath}: {f.Status}").Concat(
                result.Findings.Count > 128 ? new[] { $"Showing 128 of {result.Findings.Count} findings; full findings are included in the review report." } : []).ToArray());
        }
        catch (OperationCanceledException)
        {
            if (generation == _generation) { IntegrityStatus.Text = "Cancelled — no completed integrity result"; IntegrityProgress.Text = ""; }
        }
        catch (Exception ex)
        {
            if (generation == _generation) { IntegrityStatus.Text = "Integrity check unavailable"; Notify(InfoBarSeverity.Error, "Integrity check failed", ex.GetType().Name); }
        }
        finally
        {
            _checking = false;
            _integrityCancellation.Dispose();
            _integrityCancellation = null;
            IntegrityButton.IsEnabled = true;
            CancelIntegrityButton.IsEnabled = false;
        }
    }

    private void CancelIntegrity_Click(object sender, RoutedEventArgs e) => _integrityCancellation?.Cancel();
    private void Navigate_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string route }) App.NavigateToRoute(route);
    }
    private void CopyReport_Click(object sender, RoutedEventArgs e)
    {
        if (_assessment is null) return;
        try
        {
            var report = CognitiveImmuneSystemCoordinator.CreateReport(_assessment, _integrity);
            if (System.Text.Encoding.UTF8.GetByteCount(report) > 1024 * 1024) throw new InvalidDataException("Report exceeds its size limit.");
            var data = new DataPackage();
            data.SetText(report);
            Clipboard.SetContent(data);
            Notify(InfoBarSeverity.Success, "Review report copied", "Contains measured metadata, collection limits and any completed integrity findings. No file contents are included.");
        }
        catch (Exception ex) { Notify(InfoBarSeverity.Error, "Report copy failed", ex.GetType().Name); }
    }
    private static string Count(int? count) => count?.ToString("N0") ?? "unknown";
    private void Notify(InfoBarSeverity severity, string title, string message)
    {
        NotificationInfoBar.Severity = severity;
        NotificationInfoBar.Title = title;
        NotificationInfoBar.Message = message;
        NotificationInfoBar.IsOpen = true;
    }
}
