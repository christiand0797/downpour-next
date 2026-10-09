using System.ComponentModel;
using System.Diagnostics;
using Downpour.Core;

namespace Downpour_Desktop;

/// <summary>
/// Starts the bundled Downpour.Fixer with administrator rights (Windows shows its consent prompt) and reads the result
/// it writes into its administrator-only folder. Only the commands in <see cref="FixerProtocol"/> are ever sent.
/// </summary>
internal static class FixerClient
{
    public static string? FixerPath
    {
        get
        {
            var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
            return new[] { Path.Combine(baseDirectory, "fixer", "Downpour.Fixer.exe"), Path.Combine(baseDirectory, "Downpour.Fixer.exe") }
                .FirstOrDefault(File.Exists);
        }
    }

    public static Task<FixRunResult> ApplyAsync(IEnumerable<string> fixIds, Action<FixerStatus>? progress = null) =>
        RunAsync(FixerProtocol.Apply, string.Join(",", fixIds.Where(HardeningFixes.IsValidId).Distinct()), progress);

    public static Task<FixRunResult> UndoAsync(string backupId) => RunAsync(FixerProtocol.Undo, backupId, null);

    public static Task<FixRunResult> InstallUpdatesAsync(string scope, Action<FixerStatus>? progress) => RunAsync(FixerProtocol.Updates, scope, progress);

    private static async Task<FixRunResult> RunAsync(string verb, string argument, Action<FixerStatus>? progress)
    {
        var requestId = Guid.NewGuid().ToString("N");
        string[] args = [verb, requestId, argument];
        if (!FixerProtocol.IsValidCommand(args, out var error)) return Failure(verb, error);
        if (FixerPath is not { } path) return Failure(verb, "The fixer is missing from this Downpour folder. Extract the complete package again.");

        Process? process;
        try
        {
            var start = new ProcessStartInfo(path) { UseShellExecute = true, Verb = "runas", WorkingDirectory = Path.GetDirectoryName(path)! };
            foreach (var arg in args) start.ArgumentList.Add(arg);
            process = Process.Start(start);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return Failure(verb, "Cancelled: Windows' permission prompt was declined, so nothing was changed.");
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return Failure(verb, $"The fixer could not start ({ex.Message}).");
        }
        if (process is null) return Failure(verb, "The fixer did not start.");

        using (process)
        {
            var limit = verb == FixerProtocol.Updates ? TimeSpan.FromHours(3.1) : TimeSpan.FromMinutes(6);
            var started = DateTime.UtcNow;
            while (!process.HasExited && DateTime.UtcNow - started < limit)
            {
                await Task.Delay(1000);
                if (progress is not null && FixerProtocol.ReadJson<FixerStatus>(FixerProtocol.StatusPath(requestId)) is { } status) progress(status);
            }
        }
        return FixerProtocol.ReadJson<FixRunResult>(FixerProtocol.ResultPath(requestId)) is { } result && result.Operation == verb
            ? result
            : Failure(verb, "The fixer finished without reporting a result.");
    }

    private static FixRunResult Failure(string verb, string message) =>
        new(verb, null, [new(verb, false, message)], false, DateTimeOffset.UtcNow);

    /// <summary>A short summary for the page, plus each line.</summary>
    public static string Describe(FixRunResult result)
    {
        var ok = result.Outcomes.Count(o => o.Applied);
        var head = result.Outcomes.Count == 1 ? result.Outcomes[0].Message
            : $"{ok} of {result.Outcomes.Count} done.{(result.RebootRequired ? " Restart Windows to finish." : "")}";
        return result.Outcomes.Count == 1 ? head + (result.RebootRequired ? " Restart Windows to finish." : "")
            : head + Environment.NewLine + string.Join(Environment.NewLine, result.Outcomes.Select(o => (o.Applied ? "✓ " : "✗ ") + o.Message));
    }
}
