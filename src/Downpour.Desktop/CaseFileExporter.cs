using Downpour.Contracts;
using Downpour.Core;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace Downpour_Desktop;

/// <summary>
/// Gathers every local source into a <see cref="CaseFileBuilder"/> review file and saves it where the owner chooses, so
/// a second opinion (a person, another tool, or an AI agent of their choice) can double-check before any action.
/// </summary>
internal static class CaseFileExporter
{
    private const int MaximumActionLines = 100;

    /// <summary>Returns a short status for the caller, or null when the owner cancelled.</summary>
    public static async Task<string?> ExportAsync()
    {
        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"Downpour-Case-{DateTimeOffset.Now:yyyyMMdd-HHmmss}",
        };
        picker.FileTypeChoices.Add("Markdown case file", new List<string> { ".md" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
        var file = await picker.PickSaveFileAsync();
        if (file is null) return null;

        await App.EnsureSensorServiceAsync();
        var unavailable = new List<string>();
        var alerts = new SecurityAlertClient().TryGetSnapshotAsync();
        var databases = new ThreatDatabaseClient().GetSnapshotAsync();
        var watch = new AntiStalkerClient().TryGetSnapshotAsync();
        var hardening = new HardeningPostureClient().TryGetSnapshotAsync();
        var firewall = new FirewallInventoryClient().TryGetSnapshotAsync();
        var settings = new SensorSettingsClient().GetAsync();
        var audio = new AudioClient().TryGetSnapshotAsync();
        await Task.WhenAll(alerts, databases, watch, hardening, firewall, settings, audio);
        if (alerts.Result is null) unavailable.Add("Alert store");
        if (databases.Result?.Snapshot is null) unavailable.Add("Threat databases");
        if (watch.Result is null) unavailable.Add("Anti-stalker monitor");
        if (hardening.Result is null) unavailable.Add("Hardening checks");
        if (firewall.Result is null) unavailable.Add("Firewall inventory");
        if (settings.Result?.Settings is null) unavailable.Add("Sensor settings");
        if (audio.Result is null) unavailable.Add("Audio Shield");

        var content = CaseFileBuilder.Build(new CaseFileInputs(
            DateTimeOffset.Now,
            DesktopRelease.CurrentVersion.ToString(3),
            $"Windows {Environment.OSVersion.Version}",
            alerts.Result,
            databases.Result?.Snapshot,
            watch.Result,
            hardening.Result,
            firewall.Result,
            settings.Result?.Settings,
            await Task.Run(ReadRecentActions),
            unavailable,
            audio.Result,
            await Task.Run(ReadAuditIntegrity)));
        await FileIO.WriteTextAsync(file, content);
        return $"Saved {file.Name}. It lists program names, addresses and domains from this PC; share it only with a reviewer you trust.";
    }

    /// <summary>Runs the export from a button and reports the outcome in a dialog (live page refreshes would overwrite inline text).</summary>
    public static async Task ExportFromAsync(Microsoft.UI.Xaml.Controls.Button button)
    {
        button.IsEnabled = false;
        string? message;
        try { message = await ExportAsync(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Runtime.InteropServices.COMException)
        {
            message = $"The case file could not be saved ({ex.GetType().Name}). Choose another folder and try again.";
        }
        finally { button.IsEnabled = true; }
        if (message is null || button.XamlRoot is null) return;
        await new Microsoft.UI.Xaml.Controls.ContentDialog
        {
            Title = "Case file",
            Content = new Microsoft.UI.Xaml.Controls.TextBlock { Text = message + Environment.NewLine + Environment.NewLine + "Give it to a reviewer or AI agent of your choice to double-check every finding before you act. It contains instructions for the reviewer.", TextWrapping = Microsoft.UI.Xaml.TextWrapping.Wrap },
            CloseButtonText = "OK",
            XamlRoot = button.XamlRoot,
        }.ShowAsync();
    }

    /// <summary>Last entries of the local action audit log, so a reviewer sees what was already done (and can be undone).</summary>
    /// <summary>The service's latest audit-chain check, as a one-line summary (the service holds the key).</summary>
    private static string? ReadAuditIntegrity()
    {
        try
        {
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state", "audit-verification.v1.json");
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 8192) return null;
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            var message = root.TryGetProperty("message", out var m) ? m.GetString() : null;
            var at = root.TryGetProperty("checkedAtUtc", out var t) ? t.GetString() : null;
            return message is null ? null : $"{(message.Length <= 300 ? message : message[..300])} (checked {at ?? "unknown"} UTC by the service)";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> ReadRecentActions()
    {
        try
        {
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state", "action-audit.v1.jsonl");
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 16 * 1024 * 1024) return [];
            return File.ReadLines(path).TakeLast(MaximumActionLines).Select(line => line.Length <= 600 ? line : line[..600]).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
