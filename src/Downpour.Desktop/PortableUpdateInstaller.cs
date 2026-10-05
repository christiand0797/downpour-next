using System.Diagnostics;
using System.Text.Json;
using Downpour.Core;

namespace Downpour_Desktop;

internal static class DesktopRelease
{
    public static Version CurrentVersion { get; } = new(0, 1, 14);
}

internal sealed record UpdateInstallResult(bool Updated, bool UpToDate, string Message);

/// <summary>Downloads and verifies an update, then delegates package replacement to a separate executable.</summary>
internal static class PortableUpdateInstaller
{
    private const string StateDirectoryName = ".downpour-update";

    public static async Task<UpdateInstallResult> CheckAndStageAsync(IProgress<string> progress, CancellationToken cancellationToken = default)
    {
        var installRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        var stateRoot = Path.Combine(installRoot, StateDirectoryName);
        PrepareStateDirectory(installRoot, stateRoot);
        var created = false;
        using var client = new ReleaseUpdateClient();
        try
        {
            progress.Report("Checking the latest Downpour release…");
            var check = await client.CheckAsync(DesktopRelease.CurrentVersion, cancellationToken).ConfigureAwait(false);
            if (!check.UpdateAvailable || check.Release is null)
                return new UpdateInstallResult(false, true, $"Downpour {check.LatestVersion} is already the latest release.");

            progress.Report($"Downloading Downpour {check.LatestVersion}…");
            Directory.CreateDirectory(stateRoot);
            created = true;
            var archivePath = Path.Combine(stateRoot, "release.zip");
            await client.DownloadVerifiedPackageAsync(check.Release, archivePath, cancellationToken: cancellationToken).ConfigureAwait(false);
            var stagePath = Path.Combine(stateRoot, "stage");
            progress.Report("Verifying and staging update files…");
            var hashes = UpdateArchive.ExtractToStage(archivePath, stagePath);
            File.Delete(archivePath);
            var manifest = new StagedUpdateManifest(check.Release.Tag, new Dictionary<string, string>(hashes, StringComparer.OrdinalIgnoreCase));
            await File.WriteAllTextAsync(Path.Combine(stateRoot, "manifest.json"), JsonSerializer.Serialize(manifest), cancellationToken).ConfigureAwait(false);

            var helperSource = Path.Combine(installRoot, "update-helper", "Downpour.UpdateHelper.exe");
            if (!File.Exists(helperSource)) throw new InvalidOperationException("The package is missing its standalone update helper. Download and extract the latest portable package once, then retry in-app updates.");
            var helperDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "update-helper");
            Directory.CreateDirectory(helperDirectory);
            var helperPath = Path.Combine(helperDirectory, "Downpour.UpdateHelper.exe");
            File.Copy(helperSource, helperPath, overwrite: true);

            progress.Report("Update verified. Restarting Downpour to apply it…");
            var executable = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executable) || !Path.GetFullPath(executable).Equals(Path.Combine(installRoot, "Downpour.Desktop.exe"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The updater only supports the extracted portable Downpour.Desktop.exe installation.");

            var start = new ProcessStartInfo(helperPath) { UseShellExecute = false, WorkingDirectory = helperDirectory };
            start.ArgumentList.Add(installRoot);
            start.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            start.ArgumentList.Add(DesktopRelease.CurrentVersion.ToString(3));
            var helper = Process.Start(start);
            if (helper is null) throw new InvalidOperationException("The standalone update helper could not be started.");
            helper.Dispose();
            return new UpdateInstallResult(true, false, $"Downpour {check.LatestVersion} is staged and will finish applying as the app restarts.");
        }
        catch
        {
            if (created) TryDeleteDirectory(stateRoot);
            throw;
        }
    }

    private static void PrepareStateDirectory(string installRoot, string stateRoot)
    {
        if (!Directory.Exists(stateRoot)) return;
        var errorLog = Path.Combine(stateRoot, "update-error.txt");
        var appDataLog = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "updates", "last-update-error.txt");
        if (!File.Exists(errorLog) && !File.Exists(appDataLog))
            throw new IOException("A previous update needs attention. Review .downpour-update in the app folder before trying again.");

        EnsureSafeTree(installRoot, stateRoot);
        if (File.Exists(errorLog))
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(appDataLog)!);
                File.Copy(errorLog, appDataLog, overwrite: true);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        TryDeleteDirectory(stateRoot);
        if (Directory.Exists(stateRoot)) throw new IOException("A previous failed update could not be cleared safely. Extract a fresh portable package to a writable folder.");
    }

    private static void EnsureSafeTree(string root, string stateRoot)
    {
        if (!UpdatePathPolicy.IsStrictChildPath(root, stateRoot) || (File.GetAttributes(stateRoot) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The previous update state is not a safe directory.");
        var pending = new Stack<string>();
        pending.Push(stateRoot);
        var inspected = 0;
        while (pending.TryPop(out var directory))
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            if (++inspected > UpdateArchive.MaximumFiles + 16) throw new InvalidDataException("The previous update state contains too many entries.");
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("The previous update state contains a reparse point.");
            if (Directory.Exists(entry)) pending.Push(entry);
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }

    private sealed record StagedUpdateManifest(string Tag, Dictionary<string, string> Files);
}
