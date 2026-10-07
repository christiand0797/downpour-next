using System.Globalization;
using System.Runtime.InteropServices;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Storage.Pickers;

namespace Downpour_Desktop.Pages;

/// <summary>
/// DN-008 phase 1: user-selected quarantine and confirmed restore through the service's action pipe. The page never touches
/// the file itself; it shows the service's preview (resolved path, size, SHA-256) and returns the one-time consent token.
/// </summary>
public sealed partial class RemediationPage : Page
{
    private readonly QuarantineClient _client = new();
    private bool _busy;

    public RemediationPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_busy) return;
        SetBusy(true, "Loading the quarantine list…");
        var response = await _client.ListAsync();
        if (response is null)
        {
            await App.EnsureSensorServiceAsync();
            response = await _client.ListAsync();
        }
        SetBusy(false, "");
        if (response is null)
        {
            StatusText.Text = "The sensor service is not reachable. Quarantine needs the service that this desktop started.";
            QuarantineButton.IsEnabled = false;
            return;
        }
        if (!response.Accepted)
        {
            StatusText.Text = response.Message;
            QuarantineButton.IsEnabled = false;
            return;
        }
        QuarantineButton.IsEnabled = response.ActionsEnabled;
        StatusText.Text = response.ActionsEnabled ? "" : "Quarantine actions are turned off in Settings.";
        if (response.RecoveryNotes is { Count: > 0 } notes)
        {
            RecoveryBar.Message = string.Join("\n", notes);
            RecoveryBar.IsOpen = true;
        }
        Render(response.Items ?? [], response.ActionsEnabled);
    }

    private void Render(IReadOnlyList<QuarantineItem> items, bool actionsEnabled)
    {
        ItemsPanel.Children.Clear();
        EmptyText.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var item in items)
        {
            var details = new StackPanel { Spacing = 3 };
            details.Children.Add(new TextBlock { Text = item.FileName, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            details.Children.Add(Secondary($"From {item.OriginalPath}"));
            details.Children.Add(Secondary($"{FormatSize(item.Size)} · quarantined {item.QuarantinedAtUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)}"));
            details.Children.Add(new TextBlock { Text = item.Sha256, FontFamily = new FontFamily("Consolas"), FontSize = 11, IsTextSelectionEnabled = true, Foreground = SecondaryBrush() });
            if (item.RestoredAtUtc is { } restored)
                details.Children.Add(Secondary($"Restored {restored.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)} to {item.RestoredTo}"));

            var row = new Grid { ColumnSpacing = 12 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.Children.Add(details);
            if (item.RestoredAtUtc is null)
            {
                var buttons = new StackPanel { Spacing = 6, VerticalAlignment = VerticalAlignment.Center };
                var restore = new Button { Content = "Restore", IsEnabled = actionsEnabled, Tag = item };
                restore.Click += async (_, _) => await RestoreAsync(item, alternate: false);
                var restoreAs = new Button { Content = "Restore as…", IsEnabled = actionsEnabled, Tag = item };
                restoreAs.Click += async (_, _) => await RestoreAsync(item, alternate: true);
                buttons.Children.Add(restore);
                buttons.Children.Add(restoreAs);
                Grid.SetColumn(buttons, 1);
                row.Children.Add(buttons);
            }
            ItemsPanel.Children.Add(new Border
            {
                Padding = new Thickness(14),
                CornerRadius = new CornerRadius(10),
                BorderThickness = new Thickness(1),
                BorderBrush = new SolidColorBrush(Windows.UI.Color.FromArgb(0x57, 0x38, 0xB9, 0xD1)),
                Background = new SolidColorBrush(Windows.UI.Color.FromArgb(0xC8, 0x08, 0x11, 0x1E)),
                Child = row,
            });
        }
    }

    private async void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        Windows.Storage.StorageFile? file;
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            file = await picker.PickSingleFileAsync();
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            StatusText.Text = $"The file picker could not be opened: {exception.Message}";
            return;
        }
        if (file is null || string.IsNullOrEmpty(file.Path)) return;

        SetBusy(true, "Hashing the file in the service…");
        var preview = await _client.PreviewQuarantineAsync(file.Path);
        SetBusy(false, "");
        if (preview is null) { StatusText.Text = "The sensor service did not respond."; return; }
        if (!preview.Accepted || preview.Preview?.ConsentToken is null) { StatusText.Text = preview.Message; return; }

        var p = preview.Preview;
        var confirmed = await ConfirmAsync("Quarantine this file?",
            $"{p.TargetPath}\n\nSize: {FormatSize(p.Size)}\nSHA-256: {p.Sha256}\n\nThe file will be encrypted into Downpour's quarantine store and removed from its folder. You can restore it later from this page. Programs that use this file may stop working.",
            "Quarantine");
        if (!confirmed) { StatusText.Text = "Cancelled. Nothing was changed."; return; }

        SetBusy(true, "Quarantining…");
        var result = await _client.QuarantineAsync(p.TargetPath, p.ConsentToken);
        SetBusy(false, "");
        StatusText.Text = result?.Message ?? "The sensor service did not respond. Check the list before trying again.";
        await RefreshAsync();
        StatusText.Text = result?.Message ?? StatusText.Text;
    }

    private async Task RestoreAsync(QuarantineItem item, bool alternate)
    {
        if (_busy) return;
        string? restorePath = null;
        if (alternate)
        {
            try
            {
                var picker = new FileSavePicker { SuggestedFileName = item.FileName };
                var extension = Path.GetExtension(item.FileName);
                picker.FileTypeChoices.Add("Original type", [string.IsNullOrEmpty(extension) ? "." : extension]);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
                var target = await picker.PickSaveFileAsync();
                if (target is null) return;
                restorePath = target.Path;
                // The save picker may create an empty placeholder; restore never overwrites, so remove only that empty file.
                if (File.Exists(restorePath) && new FileInfo(restorePath).Length == 0) File.Delete(restorePath);
            }
            catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException or IOException)
            {
                StatusText.Text = $"The save dialog could not be used: {exception.Message}";
                return;
            }
        }

        SetBusy(true, "Checking the restore location…");
        var preview = await _client.PreviewRestoreAsync(item.ObjectId, restorePath);
        SetBusy(false, "");
        if (preview is null) { StatusText.Text = "The sensor service did not respond."; return; }
        if (!preview.Accepted || preview.Preview?.ConsentToken is null) { StatusText.Text = preview.Message; return; }

        var confirmed = await ConfirmAsync("Restore this file?",
            $"{item.FileName} will be decrypted, verified against its recorded SHA-256, and written to:\n\n{preview.Preview.TargetPath}\n\nOnly restore a file you are sure is safe. It was quarantined for a reason: {item.Reason}.",
            "Restore");
        if (!confirmed) { StatusText.Text = "Cancelled. Nothing was changed."; return; }

        SetBusy(true, "Restoring…");
        var result = await _client.RestoreAsync(item.ObjectId, restorePath, preview.Preview.ConsentToken);
        SetBusy(false, "");
        var message = result?.Message ?? "The sensor service did not respond.";
        await RefreshAsync();
        StatusText.Text = message;
    }

    private async Task<bool> ConfirmAsync(string title, string body, string primary)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new ScrollViewer { Content = new TextBlock { Text = body, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true }, MaxHeight = 360 },
            PrimaryButtonText = primary,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private void SetBusy(bool busy, string status)
    {
        _busy = busy;
        Busy.IsActive = busy;
        RefreshButton.IsEnabled = !busy;
        if (busy) QuarantineButton.IsEnabled = false;
        if (status.Length > 0 || busy) StatusText.Text = status;
    }

    private static TextBlock Secondary(string text) =>
        new() { Text = text, FontSize = 12, TextWrapping = TextWrapping.Wrap, Foreground = SecondaryBrush() };

    private static Brush SecondaryBrush() => (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} bytes",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes / (1024.0 * 1024):0.#} MB",
    };
}
