using System.Runtime.InteropServices;
using Downpour.Core;

namespace Downpour.Fixer;

/// <summary>
/// Finds, downloads and installs pending Windows updates (security and quality updates, optionally drivers) through the
/// Windows Update Agent, one update at a time so progress is visible. Updates that need interactive input are skipped,
/// and nothing restarts the PC: the result says when a restart is needed.
/// </summary>
internal static class WindowsUpdateInstaller
{
    public static FixRunResult Run(string scope, Action<FixerStatus> report)
    {
        FixRunResult? result = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { result = RunSta(scope, report); }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) throw failure;
        return result!;
    }

    private static FixRunResult RunSta(string scope, Action<FixerStatus> report)
    {
        var outcomes = new List<FixOutcome>();
        dynamic session = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: true)!)!;
        session.ClientApplicationID = "Downpour Next";
        report(new("searching", 2, "Asking Windows Update what this PC needs…", false, DateTimeOffset.UtcNow));
        dynamic searcher = session.CreateUpdateSearcher();
        var criteria = scope switch
        {
            "drivers" => new[] { "IsInstalled=0 and IsHidden=0 and Type='Driver'" },
            "software" => new[] { "IsInstalled=0 and IsHidden=0 and Type='Software'" },
            _ => new[] { "IsInstalled=0 and IsHidden=0 and Type='Software'", "IsInstalled=0 and IsHidden=0 and Type='Driver'" },
        };
        var pending = new List<dynamic>();
        foreach (var query in criteria)
        {
            dynamic found = searcher.Search(query);
            foreach (dynamic update in found.Updates)
            {
                // Skip updates that would stop to ask the person something (installers with their own UI).
                if ((bool)update.InstallationBehavior.CanRequestUserInput) { outcomes.Add(new(Title(update), false, "Skipped: needs to be installed interactively from Windows Update.")); continue; }
                pending.Add(update);
            }
        }
        if (pending.Count == 0)
        {
            report(new("done", 100, "No updates are waiting.", true, DateTimeOffset.UtcNow));
            return new FixRunResult(FixerProtocol.Updates, null, outcomes.Count == 0 ? [new("windows-update", true, "This PC is up to date.")] : outcomes, false, DateTimeOffset.UtcNow);
        }

        var reboot = false;
        for (var i = 0; i < pending.Count; i++)
        {
            var update = pending[i];
            var title = Title(update);
            var basePercent = 5 + i * 95 / pending.Count;
            try
            {
                if (!(bool)update.EulaAccepted) update.AcceptEula();
                dynamic collection = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.UpdateColl", throwOnError: true)!)!;
                collection.Add(update);

                report(new("downloading", basePercent, $"Downloading {i + 1} of {pending.Count}: {title}", false, DateTimeOffset.UtcNow));
                dynamic downloader = session.CreateUpdateDownloader();
                downloader.Updates = collection;
                dynamic downloaded = downloader.Download();
                if ((int)downloaded.ResultCode is not (2 or 3)) { outcomes.Add(new(title, false, $"Download failed (code {(int)downloaded.ResultCode}).")); continue; }

                report(new("installing", basePercent + 95 / pending.Count / 2, $"Installing {i + 1} of {pending.Count}: {title}", false, DateTimeOffset.UtcNow));
                dynamic installer = session.CreateUpdateInstaller();
                installer.Updates = collection;
                dynamic installed = installer.Install();
                var code = (int)installed.ResultCode;
                var needsRestart = (bool)installed.RebootRequired;
                reboot |= needsRestart;
                outcomes.Add(new(title, code is 2 or 3, code switch
                {
                    2 => needsRestart ? "Installed; finishes after a restart." : "Installed.",
                    3 => "Installed with warnings.",
                    _ => $"Install failed (code {code}, 0x{(int)installed.HResult:X8}).",
                }));
            }
            catch (COMException ex)
            {
                outcomes.Add(new(title, false, $"Windows Update error 0x{ex.HResult:X8}."));
            }
        }
        var ok = outcomes.Count(o => o.Applied);
        report(new("done", 100, $"Installed {ok} of {pending.Count} update(s).{(reboot ? " Restart to finish." : "")}", true, DateTimeOffset.UtcNow));
        return new FixRunResult(FixerProtocol.Updates, null, outcomes, reboot, DateTimeOffset.UtcNow);
    }

    private static string Title(dynamic update)
    {
        string title = update.Title ?? "Windows update";
        return title.Length > 200 ? title[..200] : title;
    }
}
