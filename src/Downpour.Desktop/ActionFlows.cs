using System.Diagnostics;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Downpour_Desktop;

/// <summary>
/// The confirm-then-act flows shared by every page: each asks the service broker for a preview, shows exactly what
/// will happen with its risks, and only acts after explicit confirmation with the one-use consent token. The broker
/// enforces the Settings switches and writes the audit record.
/// </summary>
public static class ActionFlows
{
    public static async Task EndProcessAsync(XamlRoot root, int pid, string label)
    {
        DateTimeOffset started;
        try
        {
            using var process = Process.GetProcessById(pid);
            started = process.StartTime.ToUniversalTime();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            await ShowAsync(root, "Program already closed", $"{label} (PID {pid}) is no longer running.");
            return;
        }
        var client = new ProcessTerminationClient();
        var preview = await client.PreviewTerminateAsync(pid, started);
        if (preview is null) { await App.EnsureSensorServiceAsync(); preview = await client.PreviewTerminateAsync(pid, started); }
        if (preview is null) { await ShowAsync(root, "Action broker unreachable", "Ending a program needs the local Downpour service."); return; }
        if (!preview.Accepted || preview.Preview is not { ConsentToken: not null } p)
        {
            await ShowAsync(root, "Ending this program is not allowed", preview.Message + "\n\nTurn on “Allow process termination” in Settings to permit it. Protected Windows processes are always refused.");
            return;
        }
        var text = $"End {p.ProcessName} (PID {p.ProcessId})?\n\nImage: {p.ImagePath}\nStarted: {p.StartTimeUtc.ToLocalTime():g}\n\nExpected effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\nRisks:\n• {string.Join("\n• ", p.Risks)}\n\nUnsaved work in the program will be lost. The action is written to the audit log.";
        if (!await ConfirmAsync(root, "Confirm end process", text, "End process")) return;
        var result = await client.TerminateAsync(pid, started, p.ConsentToken);
        await ShowAsync(root, result?.Accepted == true ? "Process ended" : "Process was not ended", result?.Message ?? "The broker did not confirm the action.");
    }

    public static async Task QuarantineAsync(XamlRoot root, string path, string label)
    {
        var client = new QuarantineClient();
        var preview = await client.PreviewQuarantineAsync(path);
        if (preview is null) { await App.EnsureSensorServiceAsync(); preview = await client.PreviewQuarantineAsync(path); }
        if (preview is null) { await ShowAsync(root, "Action broker unreachable", "Quarantine needs the local Downpour service."); return; }
        if (!preview.Accepted || preview.Preview is not { ConsentToken: not null } p)
        {
            await ShowAsync(root, "Quarantine is not allowed for this file", preview.Message + "\n\nTurn on “Allow quarantine actions” in Settings to permit it; Windows system files are always protected.");
            return;
        }
        var text = $"Quarantine {label}?\n\n{p.TargetPath}\n{p.Size:N0} bytes · SHA-256 {p.Sha256}\n\nThe file is encrypted into Downpour's quarantine and removed from its folder; anything that needs it stops working until it is restored from Remediation. If it is in use, end the program first.";
        if (!await ConfirmAsync(root, "Confirm quarantine", text, "Quarantine")) return;
        var result = await client.QuarantineAsync(p.TargetPath, p.ConsentToken);
        await ShowAsync(root, result?.Accepted == true ? "Quarantined" : "Not quarantined", result?.Message ?? "The broker did not confirm the action.");
    }

    public static async Task BlockIpAsync(XamlRoot root, string ip, string label)
    {
        var client = new FirewallActionClient();
        var preview = await client.PreviewBlockIpAsync(ip, reason: $"Blocked from Downpour details: {label}");
        if (preview is null) { await App.EnsureSensorServiceAsync(); preview = await client.PreviewBlockIpAsync(ip, reason: $"Blocked from Downpour details: {label}"); }
        if (preview is null) { await ShowAsync(root, "Action broker unreachable", "Blocking an address needs the local Downpour service."); return; }
        if (!preview.Accepted || preview.Preview is not { ConsentToken: not null, TargetIp: { } target } p)
        {
            await ShowAsync(root, "Blocking is not allowed", preview.Message + "\n\nTurn on firewall actions in Settings to permit temporary blocks.");
            return;
        }
        var text = $"Block {target} for {p.DurationMinutes / 60.0:0.#} hours?\n\nExpected effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\nRisks:\n• {string.Join("\n• ", p.Risks)}\n\nThe rule is temporary, can be removed from the Firewall page, and is written to the audit log.";
        if (!await ConfirmAsync(root, "Confirm block", text, "Block")) return;
        var result = await client.BlockIpAsync(target, p.ConsentToken, p.DurationMinutes, $"Blocked from Downpour details: {label}");
        await ShowAsync(root, result?.Accepted == true ? "Address blocked" : "Address not blocked", result?.Message ?? "The broker did not confirm the action.");
    }

    public static async Task ShowAsync(XamlRoot root, string title, string message) =>
        await new ContentDialog { Title = title, Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap }, CloseButtonText = "OK", XamlRoot = root }.ShowAsync();

    public static async Task<bool> ConfirmAsync(XamlRoot root, string title, string message, string primary) =>
        await new ContentDialog
        {
            Title = title,
            Content = new ScrollViewer { Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true }, MaxHeight = 420 },
            PrimaryButtonText = primary,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = root,
        }.ShowAsync() == ContentDialogResult.Primary;
}
