using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Downpour.Core;
using Microsoft.UI.Xaml;

namespace Downpour_Desktop;

internal static class DesktopRelease
{
    public static Version CurrentVersion { get; } = new(0, 1, 10);
}

internal sealed record UpdateInstallResult(bool Updated, bool UpToDate, string Message);

/// <summary>Stages a verified portable package and applies it only after the current app exits.</summary>
internal static class PortableUpdateInstaller
{
    private const string Switch = "--downpour-apply-update";
    private const string StateDirectoryName = ".downpour-update";
    private const long ApplyWaitMilliseconds = 120_000;

    public static async Task<UpdateInstallResult> CheckAndStageAsync(IProgress<string> progress, CancellationToken cancellationToken = default)
    {
        var installRoot = Path.GetFullPath(AppContext.BaseDirectory);
        var stateRoot = Path.Combine(installRoot, StateDirectoryName);
        if (Directory.Exists(stateRoot)) throw new IOException("A previous update needs attention. Review .downpour-update in the app folder before trying again.");
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
            progress.Report("Update verified. Restarting Downpour to apply it…");
            var executable = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executable) || !Path.GetFullPath(executable).Equals(Path.Combine(installRoot, "Downpour.Desktop.exe"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The updater only supports the extracted portable Downpour.Desktop.exe installation.");

            var start = new ProcessStartInfo(executable) { UseShellExecute = false, WorkingDirectory = installRoot };
            start.ArgumentList.Add(Switch);
            start.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var helper = Process.Start(start);
            if (helper is null) throw new InvalidOperationException("The update helper could not be started.");
            helper.Dispose();
            return new UpdateInstallResult(true, false, $"Downpour {check.LatestVersion} is staged and will finish applying as the app restarts.");
        }
        catch
        {
            if (created) TryDeleteDirectory(stateRoot);
            throw;
        }
    }

    /// <returns>True when the process was launched in update-helper mode.</returns>
    public static bool TryApplyAtStartup(string[] args)
    {
        var switchIndex = Array.FindIndex(args, argument => string.Equals(argument, Switch, StringComparison.Ordinal));
        if (switchIndex < 0) return false;
        var message = "The update could not be applied. Your existing Downpour files were restored where possible. The app folder may be read-only; extract the package to a folder writable by your account and try again.";
        try
        {
            if (switchIndex + 1 >= args.Length || !int.TryParse(args[switchIndex + 1], out var parentId) || parentId <= 0 || parentId == Environment.ProcessId)
                throw new InvalidDataException("The update parent process ID is invalid.");
            ApplyAfterParentExit(parentId);
            return true;
        }
        catch (Exception exception)
        {
            try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, StateDirectoryName, "update-error.txt"), $"{DateTimeOffset.UtcNow:O}\n{exception.GetType().Name}: {exception.Message}"); } catch { }
            MessageBoxW(IntPtr.Zero, message, "Downpour update", 0x10);
            return true;
        }
    }

    private static void ApplyAfterParentExit(int parentId)
    {
        var root = Path.GetFullPath(AppContext.BaseDirectory);
        var executable = Path.Combine(root, "Downpour.Desktop.exe");
        try
        {
            using var parent = Process.GetProcessById(parentId);
            var parentPath = parent.MainModule?.FileName;
            if (parentPath is null || !Path.GetFullPath(parentPath).Equals(executable, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The update requester is not the installed Downpour executable.");
            if (!parent.WaitForExit((int)ApplyWaitMilliseconds)) throw new TimeoutException("The running Downpour app did not close before the update deadline.");
        }
        catch (ArgumentException) { } // The UI may close before this helper opens the process handle.
        WaitForBundledServiceExit(root);

        var stateRoot = Path.Combine(root, StateDirectoryName);
        var stage = Path.Combine(stateRoot, "stage");
        var backup = Path.Combine(stateRoot, "backup");
        EnsureNoReparsePoints(root, stateRoot, stage);
        var manifestPath = Path.Combine(stateRoot, "manifest.json");
        var manifestInfo = new FileInfo(manifestPath);
        if (!manifestInfo.Exists || manifestInfo.Length is < 2 or > 2 * 1024 * 1024) throw new InvalidDataException("The staged update manifest is outside its size limits.");
        var manifest = JsonSerializer.Deserialize<StagedUpdateManifest>(File.ReadAllBytes(manifestPath), new JsonSerializerOptions { MaxDepth = 8 })
            ?? throw new InvalidDataException("The staged update manifest is invalid.");
        if (manifest.Files.Count is < 2 or > UpdateArchive.MaximumFiles || manifest.Tag.Length is < 5 or > 32 || !manifest.Tag.StartsWith('v') ||
            !Version.TryParse(manifest.Tag.AsSpan(1), out var releaseVersion) || releaseVersion.Build < 0 || releaseVersion.Revision != -1 || releaseVersion <= DesktopRelease.CurrentVersion)
            throw new InvalidDataException("The staged update manifest is outside its limits.");

        foreach (var entry in manifest.Files)
        {
            var relative = entry.Key.Replace('\\', '/');
            if (relative.StartsWith('/') || relative.Contains(':') || relative.Split('/').Any(part => part is ".." or ".") ||
                relative.Length > 512 || relative.Split('/').Any(part => part.Equals(StateDirectoryName, StringComparison.OrdinalIgnoreCase)) ||
                entry.Value.Length != 64 || !entry.Value.All(Uri.IsHexDigit))
                throw new InvalidDataException("The staged update contains an unsafe path.");
            var stagedFile = Path.GetFullPath(Path.Combine(stage, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!stagedFile.StartsWith(stage + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !File.Exists(stagedFile))
                throw new InvalidDataException("A staged update file is missing.");
            EnsureNoReparsePath(stage, stagedFile);
            using var input = File.OpenRead(stagedFile);
            var hash = Convert.ToHexString(SHA256.HashData(input));
            if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(hash), Convert.FromHexString(entry.Value)))
                throw new InvalidDataException("A staged update file failed integrity validation.");
        }
        if (!manifest.Files.ContainsKey("Downpour.Desktop.exe") || !manifest.Files.ContainsKey("service/Downpour.Service.exe"))
            throw new InvalidDataException("The staged update is missing required executables.");

        Directory.CreateDirectory(backup);
        EnsureNoReparsePath(root, backup);
        var changed = new List<(string Destination, string? Backup)>();
        try
        {
            foreach (var relative in manifest.Files.Keys)
            {
                var localRelative = relative.Replace('/', Path.DirectorySeparatorChar);
                var destination = Path.GetFullPath(Path.Combine(root, localRelative));
                if (!destination.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The staged update escaped the application folder.");
                var stagedFile = Path.Combine(stage, localRelative);
                var backupFile = Path.Combine(backup, localRelative);
                EnsureNoReparsePath(root, destination);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                EnsureNoReparsePath(root, destination);
                string? backupPath = null;
                if (File.Exists(destination))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(backupFile)!);
                    EnsureNoReparsePath(root, backupFile);
                    File.Copy(destination, backupFile, overwrite: false);
                    backupPath = backupFile;
                }
                changed.Add((destination, backupPath));
                var temporary = destination + ".downpour-update-" + Guid.NewGuid().ToString("N");
                File.Copy(stagedFile, temporary, overwrite: false);
                File.Move(temporary, destination, overwrite: true);
            }
            var restarted = Process.Start(new ProcessStartInfo(executable) { UseShellExecute = false, WorkingDirectory = root });
            if (restarted is null) throw new InvalidOperationException("The updated Downpour app could not be restarted.");
            restarted.Dispose();
            TryDeleteDirectory(stateRoot);
        }
        catch
        {
            for (var index = changed.Count - 1; index >= 0; index--)
            {
                var (destination, backupFile) = changed[index];
                try
                {
                    if (backupFile is not null && File.Exists(backupFile)) File.Copy(backupFile, destination, overwrite: true);
                    else if (File.Exists(destination)) File.Delete(destination);
                }
                catch { }
            }
            throw;
        }
    }

    private static void EnsureNoReparsePoints(string root, string state, string stage)
    {
        foreach (var path in new[] { root, state, stage })
        {
            if (!Directory.Exists(path)) throw new DirectoryNotFoundException("The staged update directory is missing.");
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Update directories cannot be reparse points.");
        }
    }

    private static void EnsureNoReparsePath(string rootPath, string targetPath)
    {
        var root = Path.GetFullPath(rootPath);
        var target = Path.GetFullPath(targetPath);
        var relative = Path.GetRelativePath(root, target);
        if (relative == "." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || Path.IsPathRooted(relative))
            throw new InvalidDataException("An update path escaped its trusted root.");
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var cursor = root;
        for (var index = 0; index < parts.Length; index++)
        {
            cursor = Path.Combine(cursor, parts[index]);
            if (index == parts.Length - 1 && File.Exists(cursor))
            {
                if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Update files cannot be reparse points.");
            }
            else if (Directory.Exists(cursor) && (File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Update directories cannot be reparse points.");
        }
    }

    private static void WaitForBundledServiceExit(string installRoot)
    {
        var expected = Path.GetFullPath(Path.Combine(installRoot, "service", "Downpour.Service.exe"));
        var deadline = Stopwatch.StartNew();
        while (deadline.ElapsedMilliseconds < 15_000)
        {
            var running = false;
            foreach (var process in Process.GetProcessesByName("Downpour.Service"))
            {
                using (process)
                {
                    try
                    {
                        if (process.MainModule?.FileName is { } path && Path.GetFullPath(path).Equals(expected, StringComparison.OrdinalIgnoreCase) && !process.HasExited)
                            running = true;
                    }
                    catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
                    {
                        // If the process is inaccessible, fail closed on the next iteration when it can be rechecked.
                    }
                }
            }
            if (!running) return;
            Thread.Sleep(250);
        }
        throw new TimeoutException("The bundled sensor service is still running. Close any separately started Downpour.Service process and try the update again.");
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr window, string text, string caption, uint type);

    private sealed record StagedUpdateManifest(string Tag, Dictionary<string, string> Files);
}
