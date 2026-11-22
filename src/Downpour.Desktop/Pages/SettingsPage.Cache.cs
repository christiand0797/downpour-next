using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Downpour_Desktop.Pages;

/// <summary>Settings → Storage &amp; cache: measures and clears Downpour's own cached files (see <see cref="CacheCleaner"/>).</summary>
public sealed partial class SettingsPage
{
    private readonly Dictionary<string, CheckBox> _cacheChecks = new(StringComparer.Ordinal);
    private bool _cacheBusy;

    private async Task RefreshCacheAsync()
    {
        if (_cacheBusy) return;
        _cacheBusy = true;
        try
        {
            CacheSummary.Text = "Measuring…";
            var usage = await Task.Run(() => CacheCleaner.Measure(CacheCleaner.DefaultRoot));
            RenderCache(usage);
        }
        finally { _cacheBusy = false; }
    }

    private void RenderCache(IReadOnlyList<CacheUsage> usage)
    {
        var previous = _cacheChecks.ToDictionary(p => p.Key, p => p.Value.IsChecked == true);
        _cacheChecks.Clear();
        CacheList.Children.Clear();
        foreach (var item in usage)
        {
            var check = new CheckBox
            {
                IsChecked = previous.TryGetValue(item.Category.Id, out var was) ? was : item.Category.SelectedByDefault,
                IsEnabled = item.Files > 0,
                Content = new StackPanel
                {
                    Spacing = 2,
                    Children =
                    {
                        new TextBlock { Text = $"{item.Category.Title} · {DetailDescriptions.Bytes(item.Bytes)} in {item.Files:N0} file{(item.Files == 1 ? "" : "s")}", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                        new TextBlock
                        {
                            Text = item.Category.Explanation, FontSize = 12, TextWrapping = TextWrapping.Wrap,
                            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources[item.Category.NeedsWarning ? "HudAmberBrush" : "TextFillColorSecondaryBrush"],
                        },
                    },
                },
            };
            check.Checked += (_, _) => UpdateCacheTotal(usage);
            check.Unchecked += (_, _) => UpdateCacheTotal(usage);
            _cacheChecks[item.Category.Id] = check;
            CacheList.Children.Add(check);
        }
        UpdateCacheTotal(usage);
    }

    private void UpdateCacheTotal(IReadOnlyList<CacheUsage> usage)
    {
        var total = usage.Sum(u => u.Bytes);
        var selected = usage.Where(u => _cacheChecks.TryGetValue(u.Category.Id, out var c) && c.IsChecked == true).Sum(u => u.Bytes);
        CacheSummary.Text = $"Downpour is using {DetailDescriptions.Bytes(total)} for caches · {DetailDescriptions.Bytes(selected)} selected. The action log, quarantine, alert history and settings are never removed here.";
        CleanCacheButton.IsEnabled = selected > 0;
    }

    private async void CleanCache_Click(object sender, RoutedEventArgs e)
    {
        var ids = _cacheChecks.Where(p => p.Value.IsChecked == true).Select(p => p.Key).ToArray();
        if (ids.Length == 0 || _cacheBusy) return;
        var titles = CacheCleaner.Categories.Where(c => ids.Contains(c.Id)).Select(c => (c.NeedsWarning ? "⚠ " : "• ") + c.Title);
        if (!await ActionFlows.ConfirmAsync(XamlRoot, "Clean Downpour's cache?",
                $"These will be permanently deleted:{Environment.NewLine}{string.Join(Environment.NewLine, titles)}{Environment.NewLine}{Environment.NewLine}Files Downpour is using right now are skipped.", "Delete"))
            return;
        _cacheBusy = true;
        CleanCacheButton.IsEnabled = false;
        try
        {
            CacheSummary.Text = "Cleaning…";
            var result = await Task.Run(() => CacheCleaner.Clean(CacheCleaner.DefaultRoot, ids));
            var usage = await Task.Run(() => CacheCleaner.Measure(CacheCleaner.DefaultRoot));
            RenderCache(usage);
            CacheResult.Text = $"Freed {DetailDescriptions.Bytes(result.BytesFreed)} ({result.FilesDeleted:N0} file{(result.FilesDeleted == 1 ? "" : "s")})."
                + (result.FilesInUse > 0 ? $" {result.FilesInUse} in use and kept." : "")
                + (result.FilesFailed > 0 ? $" {result.FilesFailed} could not be removed (access denied)." : "")
                + (ids.Contains(CacheCleaner.ThreatDatabases) ? " Threat databases download again on the next update." : "");
        }
        finally
        {
            _cacheBusy = false;
        }
    }

    private async void RefreshCache_Click(object sender, RoutedEventArgs e) => await RefreshCacheAsync();

    private void OpenReportsFolder_Click(object sender, RoutedEventArgs e)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "reports");
        if (!Directory.Exists(root))
        {
            WeeklyDigestState.Text = "No weekly summary has been written yet. One appears after the alert store has watched a full week.";
            return;
        }
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { root }, UseShellExecute = false })?.Dispose(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    private async void ExportPortableSettings_Click(object sender, RoutedEventArgs e)
    {
        PortableSettingsState.Text = "Choose where to save the bundle…";
        string? message;
        try { message = await PortableSettingsTransfer.ExportAsync(XamlRoot); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Runtime.InteropServices.COMException)
        {
            message = $"The bundle could not be saved ({ex.GetType().Name}). Choose another folder and try again.";
        }
        PortableSettingsState.Text = message ?? "Export cancelled. Nothing was written.";
        if (message is not null) await ActionFlows.ShowAsync(XamlRoot, "Portable preferences", message);
    }

    private async void ImportPortableSettings_Click(object sender, RoutedEventArgs e)
    {
        PortableSettingsState.Text = "Choose a bundle to open…";
        string? message;
        try { message = await PortableSettingsTransfer.ImportAsync(XamlRoot); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Runtime.InteropServices.COMException)
        {
            message = $"The bundle could not be read ({ex.GetType().Name}). Nothing was changed.";
        }
        PortableSettingsState.Text = message ?? "Import cancelled. Nothing was changed.";
        if (message is null) return;
        await ActionFlows.ShowAsync(XamlRoot, "Portable preferences", message);
        if (message.StartsWith("Applied", StringComparison.Ordinal)) SyncPreferenceToggles();
    }

    /// <summary>Re-reads the local switches after an import, without letting the toggled handlers write stale values back.</summary>
    private void SyncPreferenceToggles()
    {
        var loading = _loading;
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
            RansomwareSamplingToggle.IsOn = AppPreferences.RansomwareContentSampling;
            SoundHighToggle.IsEnabled = SoundAlarmToggle.IsOn;
        }
        finally { _loading = loading; }
        ShowSaveState();
    }

    private async void RefreshRetention_Click(object sender, RoutedEventArgs e) => await RefreshRetentionAsync();

    /// <summary>
    /// Reads the alert store's own retention facts so a missing old finding is explained where storage is managed: how much
    /// is kept, how old it is, and whether capacity is pushing evidence out before the window ends. Read-only.
    /// </summary>
    private async Task RefreshRetentionAsync()
    {
        var snapshot = await new Downpour.Core.SecurityAlertClient().TryGetSnapshotAsync();
        if (snapshot?.Retention is not { } retention)
        {
            RetentionState.Text = "Alert history is unavailable while the sensor service is offline. Open Alerts or press Refresh once it is running.";
            RetentionState.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];
            return;
        }
        var oldest = retention.OldestRetainedUtc is { } at ? $"oldest {at.ToLocalTime():g}" : "nothing stored yet";
        var evicted = retention.EvictedLast7Days == 0 ? "none evicted in 7 days" : $"{retention.EvictedLast7Days:N0} evicted in 7 days";
        RetentionState.Text = $"{retention.Retained:N0} of {retention.Capacity:N0} alerts kept over {retention.Window.TotalDays:0} days · {oldest} · {evicted}."
            + (retention.Warnings.Count == 0 ? "" : " " + string.Join(" ", retention.Warnings));
        RetentionState.Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources[
            retention.Warnings.Count > 0 ? "HudAmberBrush" : "TextFillColorSecondaryBrush"];
    }

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        var root = CacheCleaner.DefaultRoot;
        if (!Directory.Exists(root)) return;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { root }, UseShellExecute = false })?.Dispose(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }
}
