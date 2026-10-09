using Downpour.Core;
using Microsoft.UI.Xaml;

namespace Downpour_Desktop;

/// <summary>One flow for "install Windows updates" or "install driver updates" from any page, with live progress.</summary>
internal static class UpdateRunner
{
    public static bool Running { get; private set; }

    /// <param name="scope">"software", "drivers" or "all".</param>
    public static async Task<FixRunResult?> RunAsync(XamlRoot root, string scope, Action<string> report)
    {
        if (Running) { report("Updates are already being installed."); return null; }
        var what = scope switch { "drivers" => "driver updates", "software" => "Windows security and quality updates", _ => "all Windows and driver updates" };
        if (!await ActionFlows.ConfirmAsync(root, $"Install {what}?",
                $"Downpour asks Windows Update for every pending {what.Replace("all ", "")}, then downloads and installs them one by one. " +
                "Only Microsoft-signed updates offered for this PC's exact hardware and Windows version are installed. " +
                "Windows asks for permission once. Downpour never restarts the PC on its own; it tells you when a restart is needed.", "Install"))
            return null;
        Running = true;
        try
        {
            report("Starting… approve the Windows permission prompt.");
            var dispatcher = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
            var result = await FixerClient.InstallUpdatesAsync(scope, status => dispatcher.TryEnqueue(() => report($"{status.Percent}% · {status.Message}")));
            report(FixerClient.Describe(result));
            return result;
        }
        finally { Running = false; }
    }
}
