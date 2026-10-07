using System.Runtime.InteropServices;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Strictly read-only system and disk cleanup inspector.
/// Ported from v29 downpour_cleanup_module.py.
/// Calculates reclaimable space, file counts, and risk levels across temporary, cache,
/// and error directories with zero disk mutation or deletion.
/// </summary>
public static class CleanupInspector
{
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct SHQUERYRBINFO
    {
        public int cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHQueryRecycleBin(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

    public static async Task<CleanupReport> ScanAsync(CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            var categories = new List<CleanupCategory>();

            // 1. User Temp (%TEMP%)
            var userTempPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var envTemp = Path.GetTempPath();
            if (!string.IsNullOrEmpty(envTemp)) userTempPaths.Add(envTemp);
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!string.IsNullOrEmpty(localAppData))
            {
                var localTemp = Path.Combine(localAppData, "Temp");
                if (Directory.Exists(localTemp)) userTempPaths.Add(localTemp);
            }
            categories.Add(InspectPaths(
                "user_temp",
                "User Temporary Files",
                "%TEMP% and %LOCALAPPDATA%\\Temp — per-user application temporary files.",
                userTempPaths,
                "Safe",
                searchPattern: "*",
                maxDepth: 3,
                cancellationToken));

            // 2. Windows Temp (C:\Windows\Temp)
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrEmpty(winDir))
            {
                var winTemp = Path.Combine(winDir, "Temp");
                categories.Add(InspectPaths(
                    "win_temp",
                    "Windows System Temp",
                    "C:\\Windows\\Temp — system-wide installer and OS temporary files.",
                    [winTemp],
                    "Safe",
                    searchPattern: "*",
                    maxDepth: 3,
                    cancellationToken));
            }

            // 3. Thumbnail Cache
            if (!string.IsNullOrEmpty(localAppData))
            {
                var explorerCache = Path.Combine(localAppData, "Microsoft", "Windows", "Explorer");
                categories.Add(InspectPaths(
                    "thumbnails",
                    "Explorer Thumbnail Cache",
                    "Windows Explorer thumbcache_*.db caches. Safe to clear; regenerated on demand.",
                    [explorerCache],
                    "Safe",
                    searchPattern: "thumbcache_*.db",
                    maxDepth: 1,
                    cancellationToken));
            }

            // 4. Windows Error Reports (WER)
            if (!string.IsNullOrEmpty(localAppData))
            {
                var werArchive = Path.Combine(localAppData, "Microsoft", "Windows", "WER", "ReportArchive");
                var werQueue = Path.Combine(localAppData, "Microsoft", "Windows", "WER", "ReportQueue");
                categories.Add(InspectPaths(
                    "win_error_reports",
                    "Windows Error Reports",
                    "Crash dump and application error reports stored in %LOCALAPPDATA%\\WER.",
                    [werArchive, werQueue],
                    "Safe",
                    searchPattern: "*",
                    maxDepth: 3,
                    cancellationToken));
            }

            // 5. Crash Dumps
            var crashPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(localAppData))
            {
                var userCrash = Path.Combine(localAppData, "CrashDumps");
                if (Directory.Exists(userCrash)) crashPaths.Add(userCrash);
            }
            if (!string.IsNullOrEmpty(winDir))
            {
                var minidump = Path.Combine(winDir, "Minidump");
                if (Directory.Exists(minidump)) crashPaths.Add(minidump);
            }
            categories.Add(InspectPaths(
                "crash_dumps",
                "Application Crash Dumps",
                "User-mode process minidumps (.dmp) and system crash captures.",
                crashPaths,
                "Safe",
                searchPattern: "*.dmp",
                maxDepth: 2,
                cancellationToken));

            // 6. Delivery Optimization Cache
            if (!string.IsNullOrEmpty(winDir))
            {
                var deliveryOpt = Path.Combine(winDir, "SoftwareDistribution", "DeliveryOptimization");
                categories.Add(InspectPaths(
                    "delivery_opt",
                    "Delivery Optimization Cache",
                    "Peer-to-peer Windows Update peer cache packages.",
                    [deliveryOpt],
                    "Safe",
                    searchPattern: "*",
                    maxDepth: 3,
                    cancellationToken));

                // 7. Windows Update Download Cache
                var updateDownload = Path.Combine(winDir, "SoftwareDistribution", "Download");
                categories.Add(InspectPaths(
                    "win_update_cache",
                    "Windows Update Download Cache",
                    "Downloaded Windows Update installer packages.",
                    [updateDownload],
                    "Moderate",
                    searchPattern: "*",
                    maxDepth: 3,
                    cancellationToken));
            }

            // 8. Recent File Links
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (!string.IsNullOrEmpty(appData))
            {
                var recentDir = Path.Combine(appData, "Microsoft", "Windows", "Recent");
                categories.Add(InspectPaths(
                    "recent_files",
                    "Recent File Shortcuts",
                    "%APPDATA%\\Microsoft\\Windows\\Recent — shell shortcuts tracking recently opened files.",
                    [recentDir],
                    "Safe",
                    searchPattern: "*.lnk",
                    maxDepth: 1,
                    cancellationToken));
            }

            // 9. Downpour Application Reports & Logs
            var downpourPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(localAppData))
            {
                var dpReports = Path.Combine(localAppData, "Downpour", "Reports");
                if (Directory.Exists(dpReports)) downpourPaths.Add(dpReports);
                var dpLogs = Path.Combine(localAppData, "DownpourNext", "logs");
                if (Directory.Exists(dpLogs)) downpourPaths.Add(dpLogs);
            }
            if (downpourPaths.Count > 0)
            {
                categories.Add(InspectPaths(
                    "downpour_artifacts",
                    "Downpour Historical Reports",
                    "Generated HTML timeline reports and background logs.",
                    downpourPaths,
                    "Safe",
                    searchPattern: "*",
                    maxDepth: 2,
                    cancellationToken));
            }

            // 10. Recycle Bin
            categories.Add(InspectRecycleBin());

            long totalBytes = categories.Sum(c => c.TotalBytes);
            int totalFiles = categories.Sum(c => c.FileCount);

            return new CleanupReport(1, DateTimeOffset.UtcNow, totalBytes, totalFiles, categories);
        }, cancellationToken);
    }

    private static CleanupCategory InspectPaths(
        string key,
        string label,
        string description,
        IEnumerable<string> paths,
        string riskLevel,
        string searchPattern,
        int maxDepth,
        CancellationToken cancellationToken)
    {
        long totalBytes = 0;
        int fileCount = 0;
        DateTime? oldestUtc = null;
        string? largestFileName = null;
        long largestFileBytes = 0;
        var existingPaths = new List<string>();

        foreach (var dir in paths)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            existingPaths.Add(dir);

            try
            {
                InspectDirectory(dir, 1, maxDepth, searchPattern, ref totalBytes, ref fileCount, ref oldestUtc, ref largestFileName, ref largestFileBytes, cancellationToken);
            }
            catch (Exception)
            {
                // Silently swallow permission / directory access issues
            }
        }

        string? oldestFormatted = oldestUtc.HasValue ? oldestUtc.Value.ToLocalTime().ToString("yyyy-MM-dd") : null;

        return new CleanupCategory(
            key,
            label,
            description,
            totalBytes,
            fileCount,
            riskLevel,
            oldestFormatted,
            largestFileName,
            largestFileBytes > 0 ? largestFileBytes : null,
            existingPaths);
    }

    private static void InspectDirectory(
        string dirPath,
        int currentDepth,
        int maxDepth,
        string searchPattern,
        ref long totalBytes,
        ref int fileCount,
        ref DateTime? oldestUtc,
        ref string? largestFileName,
        ref long largestFileBytes,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested || currentDepth > maxDepth) return;

        try
        {
            var dirInfo = new DirectoryInfo(dirPath);
            foreach (var fi in dirInfo.EnumerateFiles(searchPattern, SearchOption.TopDirectoryOnly))
            {
                if (cancellationToken.IsCancellationRequested) return;

                try
                {
                    var len = fi.Length;
                    totalBytes += len;
                    fileCount++;

                    var lastWrite = fi.LastWriteTimeUtc;
                    if (!oldestUtc.HasValue || lastWrite < oldestUtc.Value)
                    {
                        oldestUtc = lastWrite;
                    }

                    if (len > largestFileBytes)
                    {
                        largestFileBytes = len;
                        largestFileName = fi.Name;
                    }
                }
                catch
                {
                    // File locked or inaccessible
                }
            }

            if (currentDepth < maxDepth)
            {
                foreach (var sub in dirInfo.EnumerateDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    if (cancellationToken.IsCancellationRequested) return;
                    try
                    {
                        InspectDirectory(sub.FullName, currentDepth + 1, maxDepth, searchPattern, ref totalBytes, ref fileCount, ref oldestUtc, ref largestFileName, ref largestFileBytes, cancellationToken);
                    }
                    catch
                    {
                        // Subdirectory permission or traversal error
                    }
                }
            }
        }
        catch
        {
            // Directory read access error
        }
    }

    private static CleanupCategory InspectRecycleBin()
    {
        try
        {
            var rbInfo = new SHQUERYRBINFO { cbSize = Marshal.SizeOf<SHQUERYRBINFO>() };
            int hr = SHQueryRecycleBin(null, ref rbInfo);
            if (hr == 0 && rbInfo.i64NumItems >= 0)
            {
                return new CleanupCategory(
                    "recycle_bin",
                    "Recycle Bin",
                    "System-wide deleted items awaiting permanent purge.",
                    rbInfo.i64Size,
                    (int)Math.Min(rbInfo.i64NumItems, int.MaxValue),
                    "Safe");
            }
        }
        catch
        {
            // P/Invoke failed or unsupported
        }

        return new CleanupCategory(
            "recycle_bin",
            "Recycle Bin",
            "System-wide deleted items awaiting permanent purge.",
            0,
            0,
            "Safe");
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return $"{kb:F1} KB";
        double mb = kb / 1024.0;
        if (mb < 1024) return $"{mb:F1} MB";
        double gb = mb / 1024.0;
        return $"{gb:F2} GB";
    }

    public static string GenerateTextReport(CleanupReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Downpour Disk & System Cleanup Preview Report ===");
        sb.AppendLine($"Generated: {report.ScannedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} Local");
        sb.AppendLine($"Total Potential Reclaimable Space: {FormatBytes(report.TotalReclaimableBytes)}");
        sb.AppendLine($"Total Estimated Files: {report.TotalReclaimableFiles:N0}");
        sb.AppendLine("Mode: Strictly Read-Only (Preview Mode)");
        sb.AppendLine();
        sb.AppendLine("--------------------------------------------------------------------------------");
        sb.AppendLine($"{"Category",-30} | {"Risk",-8} | {"Size",-12} | {"Files",-8} | {"Oldest",-10}");
        sb.AppendLine("--------------------------------------------------------------------------------");

        foreach (var c in report.Categories.OrderByDescending(x => x.TotalBytes))
        {
            var sizeStr = FormatBytes(c.TotalBytes);
            var oldest = c.OldestItemDate ?? "—";
            sb.AppendLine($"{c.Label,-30} | {c.RiskLevel,-8} | {sizeStr,-12} | {c.FileCount,-8:N0} | {oldest,-10}");
        }

        sb.AppendLine("--------------------------------------------------------------------------------");
        sb.AppendLine();
        sb.AppendLine("Category Descriptions:");
        foreach (var c in report.Categories)
        {
            sb.AppendLine($"• {c.Label}: {c.Description}");
        }

        return sb.ToString();
    }
}
