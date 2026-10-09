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

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        var root = CacheCleaner.DefaultRoot;
        if (!Directory.Exists(root)) return;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe") { ArgumentList = { root }, UseShellExecute = false })?.Dispose(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }
}
