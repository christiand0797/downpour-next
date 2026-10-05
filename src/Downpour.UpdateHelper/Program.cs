using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Downpour.Core;

namespace Downpour.UpdateHelper;

internal static class Program
{
    private const string StateDirectoryName = ".downpour-update";
    private const int ParentWaitMilliseconds = 120_000;

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            Apply(args);
            return 0;
        }
        catch (Exception exception)
        {
            var logPath = WriteErrorLog(exception);
            var detail = exception.Message.Length > 1200 ? exception.Message[..1200] : exception.Message;
            var message = "Downpour could not complete the update. Existing package files were restored where possible. " +
                $"Details: {exception.GetType().Name}: {detail}" +
                (logPath is null ? "" : $"\n\nLog: {logPath}") +
                "\n\nIf the app does not reopen, launch Downpour.Desktop.exe from its portable folder.";
            MessageBoxW(IntPtr.Zero, message, "Downpour update", 0x10);
            return 1;
        }
    }

    private static void Apply(string[] args)
    {
        if (args.Length != 3 || !int.TryParse(args[1], out var parentId) || parentId <= 0 || parentId == Environment.ProcessId ||
            !Version.TryParse(args[2], out var installedVersion) || installedVersion.Build < 0 || installedVersion.Revision != -1)
            throw new InvalidDataException("The update requester arguments are invalid.");

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(args[0]));
        var executable = Path.Combine(root, "Downpour.Desktop.exe");
        try
        {
            using var parent = Process.GetProcessById(parentId);
            var parentPath = parent.MainModule?.FileName;
            if (parentPath is null || !Path.GetFullPath(parentPath).Equals(executable, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The update requester is not the installed Downpour executable.");
            if (!parent.WaitForExit(ParentWaitMilliseconds)) throw new TimeoutException("Downpour did not close before the update deadline.");
        }
        catch (ArgumentException) { } // The UI may close before the helper opens the process handle.

        WaitForBundledServiceExit(root);
        var stateRoot = Path.Combine(root, StateDirectoryName);
        var stage = Path.Combine(stateRoot, "stage");
        var backup = Path.Combine(stateRoot, "backup");
        EnsureNoReparsePoints(root, stateRoot, stage);
        var manifestPath = Path.Combine(stateRoot, "manifest.json");
        var manifestInfo = new FileInfo(manifestPath);
        if (!manifestInfo.Exists || manifestInfo.Length is < 2 or > 2 * 1024 * 1024)
            throw new InvalidDataException("The staged update manifest is outside its size limits.");
        var manifest = JsonSerializer.Deserialize<StagedUpdateManifest>(File.ReadAllBytes(manifestPath), new JsonSerializerOptions { MaxDepth = 8 })
            ?? throw new InvalidDataException("The staged update manifest is invalid.");
        if (manifest.Files is null || manifest.Files.Count is < 2 or > UpdateArchive.MaximumFiles || manifest.Tag is null ||
            manifest.Tag.Length is < 5 or > 32 || !manifest.Tag.StartsWith('v') ||
            !Version.TryParse(manifest.Tag.AsSpan(1), out var releaseVersion) || releaseVersion.Build < 0 || releaseVersion.Revision != -1 || releaseVersion <= installedVersion)
            throw new InvalidDataException("The staged update manifest is outside its limits.");

        foreach (var entry in manifest.Files)
        {
            var relative = entry.Key.Replace('\\', '/');
            if (relative.StartsWith('/') || relative.Contains(':') || relative.Split('/').Any(part => part is ".." or ".") ||
                relative.Length > 512 || relative.Split('/').Any(part => part.Equals(StateDirectoryName, StringComparison.OrdinalIgnoreCase)) ||
                entry.Value is null || entry.Value.Length != 64 || !entry.Value.All(Uri.IsHexDigit))
                throw new InvalidDataException("The staged update contains an unsafe path or digest.");
            var stagedFile = Path.GetFullPath(Path.Combine(stage, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!UpdatePathPolicy.IsStrictChildPath(stage, stagedFile) || !File.Exists(stagedFile))
                throw new InvalidDataException("A staged update file is missing or escaped its staging folder.");
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
                if (!UpdatePathPolicy.IsStrictChildPath(root, destination))
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
        var relative = Path.GetRelativePath(Path.GetFullPath(rootPath), Path.GetFullPath(targetPath));
        if (!UpdatePathPolicy.IsStrictChildPath(rootPath, targetPath)) throw new InvalidDataException("An update path escaped its trusted root.");
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var cursor = Path.GetFullPath(rootPath);
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
                    catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException) { }
                }
            }
            if (!running) return;
            Thread.Sleep(250);
        }
        throw new TimeoutException("The bundled sensor service is still running. Close any separately started Downpour.Service process and try again.");
    }

    private static string? WriteErrorLog(Exception exception)
    {
        try
        {
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "updates");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "last-update-error.txt");
            File.WriteAllText(path, $"{DateTimeOffset.UtcNow:O}{Environment.NewLine}{exception.GetType().Name}: {exception.Message}");
            return path;
        }
        catch { return null; }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr window, string text, string caption, uint type);

    private sealed record StagedUpdateManifest(string Tag, Dictionary<string, string> Files);
}
