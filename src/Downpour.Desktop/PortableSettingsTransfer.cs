using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace Downpour_Desktop;

/// <summary>
/// Settings → Storage &amp; cache → Portable preferences. Moves the appearance and alert switches to another PC as one
/// passphrase-encrypted file. The content is deliberately limited to those named switches: no suppressions, no case
/// data, no setting the service owns, no machine or account detail, and no threat-feed credential.
/// </summary>
internal static class PortableSettingsTransfer
{
    private const long MaximumBundleBytes = 64 * 1024;
    private const string BundleExtension = ".dpnb";

    /// <summary>Returns the message to show, or null when the person cancelled before anything was written.</summary>
    public static async Task<string?> ExportAsync(XamlRoot root)
    {
        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"Downpour-preferences-{DateTimeOffset.Now:yyyyMMdd-HHmmss}",
        };
        picker.FileTypeChoices.Add("Downpour preferences bundle", new List<string> { BundleExtension });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
        var file = await picker.PickSaveFileAsync();
        if (file is null) return null;

        var passphrase = await AskPassphraseAsync(root, confirm: true);
        if (passphrase is null) return null;

        var values = AppPreferences.ReadPortableValues();
        var blob = PortableSettingsBundle.Encrypt(passphrase, PortablePreferences.Serialize(values));
        await FileIO.WriteBytesAsync(file, blob);
        return $"Saved {file.Name}: {blob.Length:N0} bytes holding {values.Count} preferences. "
             + "Downpour does not store the passphrase, so a forgotten one means the file cannot be opened. "
             + "Suppressions, cases, machine details and feed keys are not in it.";
    }

    /// <summary>Reads a bundle, shows exactly what would change, and applies only after the person confirms.</summary>
    public static async Task<string?> ImportAsync(XamlRoot root)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        picker.FileTypeFilter.Add(BundleExtension);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
        var file = await picker.PickSingleFileAsync();
        if (file is null) return null;
        if (string.IsNullOrEmpty(file.Path))
            return "That file is not on this PC's disk, so it cannot be read. Copy it to a folder and try again.";

        var info = new FileInfo(file.Path);
        if (!info.Exists) return "That file disappeared before it could be read.";
        if (info.Length == 0 || info.Length > MaximumBundleBytes)
            return $"That file is {(info.Length == 0 ? "empty" : "larger than 64 KiB")}, so it is not a preferences bundle. Nothing was changed.";

        var passphrase = await AskPassphraseAsync(root, confirm: false);
        if (passphrase is null) return null;

        IReadOnlyDictionary<string, bool> values;
        try
        {
            var blob = await File.ReadAllBytesAsync(file.Path);
            values = PortablePreferences.Deserialize(PortableSettingsBundle.Decrypt(passphrase, blob), AppPreferences.PortableNames);
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            return exception.Message + " Nothing was changed.";
        }

        var changes = PortablePreferences.DescribeChanges(AppPreferences.ReadPortableValues(), values);
        if (changes.Count == 0) return "Every preference in this bundle already matches this PC. Nothing was changed.";
        var summary = string.Join(Environment.NewLine, changes.Select(change => "• " + change));
        if (!await ActionFlows.ConfirmAsync(root, "Apply these preferences?",
                $"{summary}{Environment.NewLine}{Environment.NewLine}Only these switches change. Suppressions, cases, machine details and feed keys are not part of a preferences bundle.", "Apply"))
            return "Nothing was changed.";

        var applied = AppPreferences.ApplyPortableValues(values);
        StormModeController.SetAutomaticCycling(AppPreferences.AutoStormCycle);
        return $"Applied {applied} preference{(applied == 1 ? "" : "s")} from {file.Name}. "
             + "Rain, motion and storm cycling change immediately; the alert switches are read the next time an alert is graded.";
    }

    private static async Task<string?> AskPassphraseAsync(XamlRoot root, bool confirm)
    {
        var passphrase = new PasswordBox { Header = "Passphrase (at least 12 characters)", MaxLength = 256 };
        var repeat = new PasswordBox
        {
            Header = "Repeat the passphrase",
            MaxLength = 256,
            Visibility = confirm ? Visibility.Visible : Visibility.Collapsed,
        };
        var body = new StackPanel
        {
            Spacing = 8,
            MaxWidth = 460,
            Children =
            {
                new TextBlock
                {
                    Text = confirm
                        ? "The file can be opened only with this passphrase. Downpour does not store it and cannot recover it."
                        : "Type the passphrase that was chosen when the bundle was exported.",
                    TextWrapping = TextWrapping.Wrap,
                },
                passphrase,
                repeat,
            },
        };
        var dialog = new ContentDialog
        {
            Title = confirm ? "Protect the bundle" : "Open the bundle",
            Content = body,
            PrimaryButtonText = "Continue",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = root,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return null;

        var value = passphrase.Password;
        if (value.Length < PortableSettingsBundle.MinimumPassphraseLength)
        {
            await ActionFlows.ShowAsync(root, "Passphrase too short",
                $"Use at least {PortableSettingsBundle.MinimumPassphraseLength} characters.");
            return null;
        }
        if (confirm && !string.Equals(value, repeat.Password, StringComparison.Ordinal))
        {
            await ActionFlows.ShowAsync(root, "Passphrases do not match",
                "Type the same passphrase twice so the bundle can be opened later.");
            return null;
        }
        return value;
    }
}
