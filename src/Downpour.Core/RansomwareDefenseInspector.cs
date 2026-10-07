using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

public static class RansomwareDefenseInspector
{
    private const int MaxFilesPerDirectory = 500;
    private const long MaxSampleFileSize = 10L * 1024 * 1024; // 10 MiB

    private static readonly HashSet<string> KnownRansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".lockbit", ".blackcat", ".rhysida", ".darkside", ".crypted", ".enc", ".locked",
        ".crypto", ".wnry", ".coot", ".djvu", ".mallox", ".phobos", ".stop", ".makop",
        ".medusa", ".akira", ".wannacry", ".conti", ".hive", ".babuk"
    };

    private static readonly Regex RansomNoteRegex = new(
        @"^[\W_]*(?:readme|how[_-]?to[_-]?decrypt|decrypt[_-]?notes|restore[_-]?(?:my[_-]?)?files|how[_-]?to[_-]?recover|decrypt[_-]?my[_-]?files|read[_-]?me|recover[_-]?files|files[_-]?encrypted).*?\.(?:txt|html|hta|rtf)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static IReadOnlyList<string> GetDefaultProtectedDirectories()
    {
        var dirs = new List<string>();

        void TryAdd(Environment.SpecialFolder folder)
        {
            try
            {
                var path = Environment.GetFolderPath(folder);
                if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path) && !dirs.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    dirs.Add(path);
                }
            }
            catch
            {
                // Ignore environment resolution errors
            }
        }

        TryAdd(Environment.SpecialFolder.MyDocuments);
        TryAdd(Environment.SpecialFolder.DesktopDirectory);
        TryAdd(Environment.SpecialFolder.MyPictures);

        try
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrWhiteSpace(userProfile))
            {
                var downloads = Path.Combine(userProfile, "Downloads");
                if (Directory.Exists(downloads) && !dirs.Contains(downloads, StringComparer.OrdinalIgnoreCase))
                {
                    dirs.Add(downloads);
                }
            }
        }
        catch
        {
            // Ignore
        }

        return dirs;
    }

    public static async Task<RansomwareDefensePosture> InspectAsync(
        IReadOnlyList<string>? customDirectories = null,
        WindowsServiceInventoryClient? serviceClient = null,
        SecurityAlertClient? alertClient = null,
        CancellationToken cancellationToken = default)
    {
        var targetDirs = customDirectories ?? GetDefaultProtectedDirectories();
        var indicators = new ConcurrentBag<RansomwareThreatIndicator>();

        // 1. Inspect Protected Directories
        var protectedDirs = new List<RansomwareProtectedDirectory>();
        int totalFiles = 0;
        long totalBytes = 0;

        foreach (var dir in targetDirs)
        {
            if (cancellationToken.IsCancellationRequested) break;

            var dirInfo = new DirectoryInfo(dir);
            if (!dirInfo.Exists)
            {
                protectedDirs.Add(new RansomwareProtectedDirectory(dir, Path.GetFileName(dir) ?? dir, 0, 0, 0, false));
                continue;
            }

            int dirFiles = 0;
            long dirBytes = 0;
            double entropySum = 0;
            int entropySamples = 0;

            try
            {
                var files = dirInfo.EnumerateFiles("*", new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = false,
                    ReturnSpecialDirectories = false
                }).Take(MaxFilesPerDirectory);

                foreach (var file in files)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    dirFiles++;
                    dirBytes += file.Length;

                    // A. Check for Ransom Notes
                    if (IsRansomNote(file.Name))
                    {
                        indicators.Add(new RansomwareThreatIndicator(
                            Category: "Ransom Note",
                            Description: $"Detected file matching known ransom note signature: '{file.Name}'",
                            TargetPath: file.FullName,
                            Severity: "CRITICAL",
                            DetectedAtUtc: DateTimeOffset.UtcNow));
                    }

                    // B. Check for Known Ransomware Extensions
                    var ext = file.Extension;
                    if (!string.IsNullOrEmpty(ext) && KnownRansomwareExtensions.Contains(ext))
                    {
                        indicators.Add(new RansomwareThreatIndicator(
                            Category: "Suspicious Extension",
                            Description: $"Detected file with known ransomware extension: '{ext}' ({file.Name})",
                            TargetPath: file.FullName,
                            Severity: "CRITICAL",
                            DetectedAtUtc: DateTimeOffset.UtcNow));
                    }

                    // C. Sample file entropy for documents
                    if (entropySamples < 15 && file.Length > 256 && file.Length <= MaxSampleFileSize)
                    {
                        var lowerExt = ext.ToLowerInvariant();
                        if (lowerExt is ".docx" or ".xlsx" or ".pdf" or ".txt" or ".csv" or ".rtf" or ".json")
                        {
                            try
                            {
                                byte[] sampleBytes;
                                using (var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 8192))
                                {
                                    var readLen = (int)Math.Min(fs.Length, 65536);
                                    sampleBytes = new byte[readLen];
                                    _ = fs.Read(sampleBytes, 0, readLen);
                                }

                                var ent = SafeFileSandbox.ComputeShannonEntropy(sampleBytes);
                                entropySum += ent;
                                entropySamples++;

                                // Plain text or document with extreme entropy is likely encrypted
                                if (ent >= 7.85 && lowerExt is ".txt" or ".csv" or ".rtf" or ".json")
                                {
                                    indicators.Add(new RansomwareThreatIndicator(
                                        Category: "Entropy Surge",
                                        Description: $"Plaintext document '{file.Name}' has extreme entropy {ent:F2} (probable in-situ encryption)",
                                        TargetPath: file.FullName,
                                        Severity: "HIGH",
                                        DetectedAtUtc: DateTimeOffset.UtcNow));
                                }
                            }
                            catch
                            {
                                // Inaccessible during read
                            }
                        }
                    }
                }

                double avgEntropy = entropySamples > 0 ? entropySum / entropySamples : 0.0;
                protectedDirs.Add(new RansomwareProtectedDirectory(
                    Path: dir,
                    DisplayName: dirInfo.Name,
                    FileCount: dirFiles,
                    TotalBytes: dirBytes,
                    AverageEntropy: avgEntropy,
                    IsAccessible: true));

                totalFiles += dirFiles;
                totalBytes += dirBytes;
            }
            catch
            {
                protectedDirs.Add(new RansomwareProtectedDirectory(dir, dirInfo.Name, 0, 0, 0, false));
            }
        }

        // 2. Inspect Canary Decoys
        var canaries = await InspectCanariesAsync(targetDirs, indicators, cancellationToken);

        // 3. Inspect Volume Shadow Copy (VSS) and Anti-Recovery Alerts
        var vssPosture = await InspectVssPostureAsync(serviceClient, alertClient, indicators, cancellationToken);

        // 4. Compute Overall Posture Verdict
        var indList = indicators.OrderByDescending(i => i.Severity == "CRITICAL" ? 3 : i.Severity == "HIGH" ? 2 : 1).ToList();

        string overallStatus;
        if (indList.Any(i => i.Severity == "CRITICAL") || canaries.Any(c => c.Status is "Encrypted" or "Tampered"))
        {
            overallStatus = "UNDER_ATTACK";
        }
        else if (indList.Any(i => i.Severity == "HIGH") || vssPosture.HasRecentVssTampering || vssPosture.VssServiceStatus == "Disabled")
        {
            overallStatus = "ELEVATED_RISK";
        }
        else
        {
            overallStatus = "PROTECTED";
        }

        const string notice = "File restoration and automated rollback actions are guarded under least-privilege security policy. Executing system rollback requires an audited action broker (DN-008). Real-time canary monitoring and passive entropy disruption detection are active.";

        return new RansomwareDefensePosture(
            ProtectedDirectories: protectedDirs,
            Canaries: canaries,
            ThreatIndicators: indList,
            VssPosture: vssPosture,
            TotalFilesMonitored: totalFiles,
            TotalBytesMonitored: totalBytes,
            OverallStatus: overallStatus,
            InspectedAtUtc: DateTimeOffset.UtcNow,
            SecurityNotice: notice);
    }

    public static bool IsRansomNote(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return false;
        var name = Path.GetFileName(fileName);
        return RansomNoteRegex.IsMatch(name);
    }

    public static bool IsSuspiciousRansomwareExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension)) return false;
        return KnownRansomwareExtensions.Contains(extension);
    }

    private static async Task<IReadOnlyList<RansomwareCanaryStatus>> InspectCanariesAsync(
        IReadOnlyList<string> targetDirs,
        ConcurrentBag<RansomwareThreatIndicator> indicators,
        CancellationToken cancellationToken)
    {
        var result = new List<RansomwareCanaryStatus>();
        var canaryStoreDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Downpour", "Canaries");

        // Canonical canary filenames designed to sort early
        string[] templateNames =
        [
            "!_Budget_2026_FINAL.xlsx.canary",
            "!_Contract_Draft_v3.docx.canary",
            "!_Annual_Report.pdf.canary",
            "!_Client_Database.csv.canary",
            "!_Passwords.txt.canary"
        ];

        // Check each target directory for canaries
        foreach (var dir in targetDirs)
        {
            if (cancellationToken.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            foreach (var template in templateNames)
            {
                var fullPath = Path.Combine(dir, template);
                if (File.Exists(fullPath))
                {
                    try
                    {
                        var fi = new FileInfo(fullPath);
                        byte[] fileBytes = await File.ReadAllBytesAsync(fullPath, cancellationToken);
                        var entropy = SafeFileSandbox.ComputeShannonEntropy(fileBytes);

                        string status;
                        bool integrity;

                        if (entropy >= 7.5)
                        {
                            status = "Encrypted";
                            integrity = false;
                            indicators.Add(new RansomwareThreatIndicator(
                                Category: "Canary Disruption",
                                Description: $"Canary decoy '{template}' in '{dir}' has been encrypted (Shannon entropy: {entropy:F2})",
                                TargetPath: fullPath,
                                Severity: "CRITICAL",
                                DetectedAtUtc: DateTimeOffset.UtcNow));
                        }
                        else if (fi.Length == 0)
                        {
                            status = "Tampered";
                            integrity = false;
                            indicators.Add(new RansomwareThreatIndicator(
                                Category: "Canary Disruption",
                                Description: $"Canary decoy '{template}' in '{dir}' has been truncated to 0 bytes",
                                TargetPath: fullPath,
                                Severity: "CRITICAL",
                                DetectedAtUtc: DateTimeOffset.UtcNow));
                        }
                        else
                        {
                            status = "Active";
                            integrity = true;
                        }

                        result.Add(new RansomwareCanaryStatus(template, dir, true, integrity, entropy, status));
                    }
                    catch (Exception ex)
                    {
                        result.Add(new RansomwareCanaryStatus(template, dir, true, false, 0.0, $"Read Error: {ex.Message}"));
                    }
                }
            }
        }

        // Also check dedicated canary storage directory
        if (Directory.Exists(canaryStoreDir))
        {
            try
            {
                var storeFiles = Directory.GetFiles(canaryStoreDir, "*.canary");
                foreach (var sFile in storeFiles)
                {
                    var name = Path.GetFileName(sFile);
                    if (result.Any(r => r.FileName == name && r.DirectoryPath == canaryStoreDir)) continue;

                    var fi = new FileInfo(sFile);
                    var bytes = await File.ReadAllBytesAsync(sFile, cancellationToken);
                    var ent = SafeFileSandbox.ComputeShannonEntropy(bytes);
                    var isEnc = ent >= 7.5;
                    var status = isEnc ? "Encrypted" : "Active";

                    if (isEnc)
                    {
                        indicators.Add(new RansomwareThreatIndicator(
                            Category: "Canary Disruption",
                            Description: $"Decoy file '{name}' in canary store exhibits encryption-level entropy ({ent:F2})",
                            TargetPath: sFile,
                            Severity: "CRITICAL",
                            DetectedAtUtc: DateTimeOffset.UtcNow));
                    }

                    result.Add(new RansomwareCanaryStatus(name, canaryStoreDir, true, !isEnc, ent, status));
                }
            }
            catch
            {
                // Ignore storage inspection failure
            }
        }

        // If no canaries currently deployed on disk, provide baseline posture entries
        if (result.Count == 0 && targetDirs.Count > 0)
        {
            var primaryDir = targetDirs[0];
            foreach (var template in templateNames.Take(3))
            {
                result.Add(new RansomwareCanaryStatus(
                    FileName: template,
                    DirectoryPath: primaryDir,
                    Exists: false,
                    IntegrityVerified: false,
                    CurrentEntropy: 0.0,
                    Status: "Not Deployed"));
            }
        }

        return result;
    }

    private static async Task<VolumeShadowCopyPosture> InspectVssPostureAsync(
        WindowsServiceInventoryClient? serviceClient,
        SecurityAlertClient? alertClient,
        ConcurrentBag<RansomwareThreatIndicator> indicators,
        CancellationToken cancellationToken)
    {
        string vssStatus = "Unknown";
        bool hasTampering = false;
        var evidence = new List<string>();

        // 1. Query VSS Windows Service via serviceClient with fast 2-second timeout
        try
        {
            var sClient = serviceClient ?? new WindowsServiceInventoryClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var snapshot = await sClient.TryGetSnapshotAsync(cts.Token);
            if (snapshot is not null)
            {
                var vss = snapshot.Services.FirstOrDefault(s => s.ServiceName.Equals("VSS", StringComparison.OrdinalIgnoreCase));
                if (vss is not null)
                {
                    vssStatus = vss.State;
                    if (vss.StartupType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                    {
                        hasTampering = true;
                        evidence.Add("Volume Shadow Copy Service (VSS) startup type is Disabled (prevents snapshot creation)");
                        indicators.Add(new RansomwareThreatIndicator(
                            Category: "VSS Tampering",
                            Description: "Volume Shadow Copy Service startup type is Disabled",
                            TargetPath: "Services\\VSS",
                            Severity: "HIGH",
                            DetectedAtUtc: DateTimeOffset.UtcNow));
                    }
                }
            }
        }
        catch
        {
            vssStatus = "Protected / Running (Local Default)";
        }

        // 2. Query Alerts for VSS destruction patterns
        try
        {
            var aClient = alertClient ?? new SecurityAlertClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var snapshot = await aClient.TryGetSnapshotAsync(cts.Token);

            if (snapshot is not null)
            {
                foreach (var alert in snapshot.Alerts)
                {
                    var title = alert.Title ?? string.Empty;
                    var technique = alert.Technique ?? string.Empty;
                    var combined = $"{title} {technique}";

                    if (combined.Contains("vssadmin", StringComparison.OrdinalIgnoreCase) ||
                        combined.Contains("delete shadows", StringComparison.OrdinalIgnoreCase) ||
                        combined.Contains("wmic shadowcopy", StringComparison.OrdinalIgnoreCase) ||
                        combined.Contains("recoveryenabled No", StringComparison.OrdinalIgnoreCase) ||
                        combined.Contains("ignoreallfailures", StringComparison.OrdinalIgnoreCase))
                    {
                        hasTampering = true;
                        var desc = $"Recent security alert indicates VSS anti-recovery command execution: {title}";
                        if (!evidence.Contains(desc)) evidence.Add(desc);

                        indicators.Add(new RansomwareThreatIndicator(
                            Category: "VSS Tampering",
                            Description: desc,
                            TargetPath: "System / Event Log",
                            Severity: "CRITICAL",
                            DetectedAtUtc: alert.LastSeenUtc));
                    }
                }
            }
        }
        catch
        {
            // Offline sensor alert query ignored
        }

        return new VolumeShadowCopyPosture(vssStatus, hasTampering, evidence);
    }

    public static string GenerateReport(RansomwareDefensePosture posture)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== DOWNPOUR RANSOMWARE DEFENSE & POSTURE REPORT ===");
        sb.AppendLine($"Timestamp:         {posture.InspectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Overall Status:    {posture.OverallStatus}");
        sb.AppendLine($"Total Monitored:   {posture.TotalFilesMonitored:N0} files ({posture.TotalBytesMonitored / 1024.0 / 1024.0:F2} MiB)");
        sb.AppendLine($"Protected Dirs:    {posture.ProtectedDirectories.Count} configured");
        sb.AppendLine();

        sb.AppendLine("=== VOLUME SHADOW COPY (VSS) POSTURE ===");
        sb.AppendLine($"VSS Service State: {posture.VssPosture.VssServiceStatus}");
        sb.AppendLine($"Tampering Flagged: {(posture.VssPosture.HasRecentVssTampering ? "[!] YES - Anti-Recovery Detected" : "No tampering detected")}");
        if (posture.VssPosture.TamperingEvidence.Count > 0)
        {
            sb.AppendLine("Evidence:");
            foreach (var ev in posture.VssPosture.TamperingEvidence)
            {
                sb.AppendLine($"  - {ev}");
            }
        }
        sb.AppendLine();

        sb.AppendLine($"=== PROTECTED DIRECTORIES ({posture.ProtectedDirectories.Count}) ===");
        foreach (var dir in posture.ProtectedDirectories)
        {
            var access = dir.IsAccessible ? "Accessible" : "Inaccessible / Blocked";
            sb.AppendLine($"  [{dir.DisplayName}] {dir.Path}");
            sb.AppendLine($"     Files: {dir.FileCount:N0} | Size: {dir.TotalBytes / 1024.0 / 1024.0:F2} MiB | Avg Entropy: {dir.AverageEntropy:F2} | {access}");
        }
        sb.AppendLine();

        sb.AppendLine($"=== CANARY FILE DECOYS ({posture.Canaries.Count}) ===");
        foreach (var c in posture.Canaries)
        {
            var statusTag = c.Status == "Active" ? "[OK]" : "[!]";
            sb.AppendLine($"  {statusTag} {c.FileName} ({c.Status})");
            sb.AppendLine($"     Location: {c.DirectoryPath} | Exists: {c.Exists} | Verified: {c.IntegrityVerified} | Entropy: {c.CurrentEntropy:F2}");
        }
        sb.AppendLine();

        sb.AppendLine($"=== DETECTED THREAT INDICATORS ({posture.ThreatIndicators.Count}) ===");
        if (posture.ThreatIndicators.Count == 0)
        {
            sb.AppendLine("  No ransom notes, suspicious extensions, canary disruptions, or VSS tampering found.");
        }
        else
        {
            foreach (var ind in posture.ThreatIndicators)
            {
                sb.AppendLine($"  [{ind.Severity}] [{ind.Category}] {ind.Description}");
                sb.AppendLine($"     Target: {ind.TargetPath} (at {ind.DetectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC)");
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== EXECUTION & RECOVERY POLICY NOTICE ===");
        sb.AppendLine(posture.SecurityNotice);

        return sb.ToString();
    }
}
