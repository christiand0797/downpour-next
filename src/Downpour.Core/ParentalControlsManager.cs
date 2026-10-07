using System.Diagnostics;
using System.Globalization;
using System.Text;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>
/// Manages parental control posture evaluation, screen time scheduling,
/// web category filter analysis, and restricted application checks.
/// Modifying system hosts files remains strictly guarded under least-privilege policy (DN-008).
/// </summary>
public sealed class ParentalControlsManager
{
    public const string HostsFilterMarkerStart = "# === DOWNPOUR NEXT - PARENTAL CONTROLS START ===";
    public const string HostsFilterMarkerEnd = "# === DOWNPOUR NEXT - PARENTAL CONTROLS END ===";

    private static readonly Dictionary<string, IReadOnlyList<string>> CategoryDomainMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["adult"] =
        [
            "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "onlyfans.com",
            "chaturbate.com", "livejasmin.com", "stripchat.com", "youporn.com"
        ],
        ["gambling"] =
        [
            "bet365.com", "888casino.com", "pokerstars.com", "draftkings.com",
            "fanduel.com", "bovada.lv", "stake.com", "betfair.com"
        ],
        ["violence"] =
        [
            "bestgore.com", "liveleak.com", "documentingreality.com", "theync.com", "crazyshit.com"
        ],
        ["weapons"] =
        [
            "armslist.com", "gunbroker.com", "brownells.com", "midwayusa.com", "budsgunshop.com"
        ],
        ["drugs"] =
        [
            "silkroad.onion", "cannabis.net", "high-times.com", "leafly.com", "rollitup.org"
        ]
    };

    private readonly string _configFilePath;
    private readonly string _defaultHostsFilePath;
    private ParentalControlsConfig _config;

    public ParentalControlsManager(string? configFilePath = null, string? hostsFilePath = null)
    {
        _configFilePath = configFilePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DownpourNext",
            "parental_config.json");

        _defaultHostsFilePath = hostsFilePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        _config = LoadOrCreateDefaultConfig();
    }

    /// <summary>
    /// Gets the current parental controls configuration.
    /// </summary>
    public ParentalControlsConfig CurrentConfig => _config;

    /// <summary>
    /// Updates the active configuration and saves to disk.
    /// </summary>
    public void SaveConfig(ParentalControlsConfig newConfig)
    {
        _config = newConfig;
        try
        {
            var dir = Path.GetDirectoryName(_configFilePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string json = JsonConvert.SerializeObject(newConfig, Formatting.Indented);
            File.WriteAllText(_configFilePath, json);
        }
        catch
        {
            // Fallback for restricted storage environments
        }
    }

    /// <summary>
    /// Evaluates real-time screen time usage against weekday/weekend limits and bedtime curfew.
    /// </summary>
    public static ScreenTimeStatus EvaluateScreenTime(
        ScreenTimeSchedule schedule,
        DateTimeOffset now,
        int currentUsageMinutes)
    {
        if (!schedule.Enabled)
        {
            return new ScreenTimeStatus(
                IsWithinCurfew: false,
                CurfewMessage: "Screen time scheduling is currently disabled.",
                TodayUsageMinutes: currentUsageMinutes,
                TodayLimitMinutes: 0,
                RemainingMinutes: 0,
                IsLimitExceeded: false,
                WarningPercent: 0.0);
        }

        bool isWeekend = now.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday;
        int limitMinutes = isWeekend ? schedule.WeekendLimitMinutes : schedule.WeekdayLimitMinutes;
        int remainingMinutes = Math.Max(0, limitMinutes - currentUsageMinutes);
        bool isLimitExceeded = limitMinutes > 0 && currentUsageMinutes >= limitMinutes;
        double warningPercent = limitMinutes > 0 ? (double)currentUsageMinutes / limitMinutes * 100.0 : 0.0;

        // Bedtime evaluation
        bool isCurfew = IsTimeWithinCurfew(now.TimeOfDay, schedule.BedtimeStart, schedule.BedtimeEnd);
        string curfewMessage = isCurfew
            ? $"Bedtime curfew is active ({schedule.BedtimeStart} to {schedule.BedtimeEnd}). Computer access is restricted."
            : $"Access allowed. Bedtime curfew starts at {schedule.BedtimeStart}.";

        return new ScreenTimeStatus(
            IsWithinCurfew: isCurfew,
            CurfewMessage: curfewMessage,
            TodayUsageMinutes: currentUsageMinutes,
            TodayLimitMinutes: limitMinutes,
            RemainingMinutes: remainingMinutes,
            IsLimitExceeded: isLimitExceeded,
            WarningPercent: Math.Round(warningPercent, 1));
    }

    /// <summary>
    /// Collects the list of domain names to be blocked based on selected policy categories and custom additions.
    /// </summary>
    public static IReadOnlyList<string> GetDomainsToBlock(WebFilterPolicy policy)
    {
        if (!policy.Enabled) return [];

        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (policy.BlockAdultContent && CategoryDomainMap.TryGetValue("adult", out var adultDomains))
            foreach (var d in adultDomains) domains.Add(d);

        if (policy.BlockGambling && CategoryDomainMap.TryGetValue("gambling", out var gamblingDomains))
            foreach (var d in gamblingDomains) domains.Add(d);

        if (policy.BlockViolence && CategoryDomainMap.TryGetValue("violence", out var violenceDomains))
            foreach (var d in violenceDomains) domains.Add(d);

        if (policy.BlockWeapons && CategoryDomainMap.TryGetValue("weapons", out var weaponsDomains))
            foreach (var d in weaponsDomains) domains.Add(d);

        if (policy.BlockDrugs && CategoryDomainMap.TryGetValue("drugs", out var drugsDomains))
            foreach (var d in drugsDomains) domains.Add(d);

        if (policy.CustomBlockedDomains is { Count: > 0 })
        {
            foreach (var custom in policy.CustomBlockedDomains)
            {
                var clean = CleanDomain(custom);
                if (!string.IsNullOrWhiteSpace(clean))
                {
                    domains.Add(clean);
                }
            }
        }

        return domains.OrderBy(d => d).ToList();
    }

    /// <summary>
    /// Inspects the Windows hosts file (read-only) to evaluate current DNS filtering posture.
    /// </summary>
    public HostsFileFilterPosture InspectHostsFile(string? customHostsPath = null)
    {
        string path = customHostsPath ?? _defaultHostsFilePath;

        try
        {
            if (!File.Exists(path))
            {
                return new HostsFileFilterPosture(
                    HostsFilePath: path,
                    IsAccessible: false,
                    HasDownpourFilterMarker: false,
                    ActiveBlockedDomainsCount: 0,
                    LastUpdatedUtc: null);
            }

            string content = File.ReadAllText(path);
            bool hasMarker = content.Contains(HostsFilterMarkerStart, StringComparison.OrdinalIgnoreCase);
            int blockedCount = 0;

            if (hasMarker)
            {
                int startIndex = content.IndexOf(HostsFilterMarkerStart, StringComparison.OrdinalIgnoreCase);
                int endIndex = content.IndexOf(HostsFilterMarkerEnd, StringComparison.OrdinalIgnoreCase);

                if (startIndex >= 0 && endIndex > startIndex)
                {
                    string block = content[startIndex..endIndex];
                    var lines = block.Split('\n');
                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();
                        if (trimmed.StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase))
                        {
                            blockedCount++;
                        }
                    }
                }
            }

            var lastModified = File.GetLastWriteTimeUtc(path);

            return new HostsFileFilterPosture(
                HostsFilePath: path,
                IsAccessible: true,
                HasDownpourFilterMarker: hasMarker,
                ActiveBlockedDomainsCount: blockedCount,
                LastUpdatedUtc: lastModified);
        }
        catch
        {
            return new HostsFileFilterPosture(
                HostsFilePath: path,
                IsAccessible: false,
                HasDownpourFilterMarker: false,
                ActiveBlockedDomainsCount: 0,
                LastUpdatedUtc: null);
        }
    }

    /// <summary>
    /// Formats hosts file content with Downpour filter entries without modifying the system file.
    /// </summary>
    public static string FormatHostsFileWithFilter(string existingContent, IReadOnlyCollection<string> domainsToBlock)
    {
        // Strip previous Downpour block if exists
        string cleanedContent = existingContent;
        if (cleanedContent.Contains(HostsFilterMarkerStart, StringComparison.OrdinalIgnoreCase) &&
            cleanedContent.Contains(HostsFilterMarkerEnd, StringComparison.OrdinalIgnoreCase))
        {
            int start = cleanedContent.IndexOf(HostsFilterMarkerStart, StringComparison.OrdinalIgnoreCase);
            int end = cleanedContent.IndexOf(HostsFilterMarkerEnd, StringComparison.OrdinalIgnoreCase) + HostsFilterMarkerEnd.Length;
            cleanedContent = (cleanedContent[..start] + cleanedContent[end..]).Trim();
        }

        if (domainsToBlock.Count == 0)
        {
            return cleanedContent;
        }

        var sb = new StringBuilder(cleanedContent);
        if (sb.Length > 0 && !cleanedContent.EndsWith("\n"))
        {
            sb.AppendLine();
        }

        sb.AppendLine();
        sb.AppendLine(HostsFilterMarkerStart);
        sb.AppendLine($"# Generated by Downpour Next Parental Controls on {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"# Total blocked domains: {domainsToBlock.Count}");

        foreach (var domain in domainsToBlock.OrderBy(d => d))
        {
            sb.AppendLine($"127.0.0.1 {domain}");
            if (!domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"127.0.0.1 www.{domain}");
            }
        }

        sb.AppendLine(HostsFilterMarkerEnd);

        return sb.ToString();
    }

    /// <summary>
    /// Checks running processes against the configured app restriction policy.
    /// </summary>
    public static IReadOnlyList<string> CheckActiveRestrictedApps(
        AppRestrictionPolicy policy,
        IReadOnlyList<string>? simulatedProcessNames = null)
    {
        if (!policy.Enabled || policy.BlockedExecutableNames is not { Count: > 0 })
        {
            return [];
        }

        var blockedSet = new HashSet<string>(policy.BlockedExecutableNames, StringComparer.OrdinalIgnoreCase);
        var detected = new List<string>();

        if (simulatedProcessNames is not null)
        {
            foreach (var name in simulatedProcessNames)
            {
                string cleanName = NormalizeExeName(name);
                if (blockedSet.Contains(cleanName) || blockedSet.Contains(name))
                {
                    detected.Add(name);
                }
            }
            return detected;
        }

        try
        {
            var processes = Process.GetProcesses();
            foreach (var p in processes)
            {
                try
                {
                    string name = p.ProcessName;
                    string exeName = name + ".exe";
                    if (blockedSet.Contains(exeName) || blockedSet.Contains(name))
                    {
                        if (!detected.Contains(exeName, StringComparer.OrdinalIgnoreCase))
                        {
                            detected.Add(exeName);
                        }
                    }
                }
                catch
                {
                    // Access denied or exited
                }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch
        {
            // Process enumeration restricted
        }

        return detected;
    }

    /// <summary>
    /// Captures a complete point-in-time posture snapshot for parental controls.
    /// </summary>
    public ParentalPostureSnapshot CapturePostureSnapshot(
        int currentUsageMinutes = 0,
        DateTimeOffset? evaluatedAt = null,
        IReadOnlyList<string>? simulatedProcesses = null,
        IReadOnlyList<ParentalActivityLogEntry>? logs = null)
    {
        var now = evaluatedAt ?? DateTimeOffset.UtcNow;
        var screenTime = EvaluateScreenTime(_config.ScreenTime, now, currentUsageMinutes);
        var hostsPosture = InspectHostsFile();
        var restrictedApps = CheckActiveRestrictedApps(_config.AppRestrictions, simulatedProcesses);

        return new ParentalPostureSnapshot(
            CapturedAtUtc: now,
            Config: _config,
            ScreenTime: screenTime,
            HostsPosture: hostsPosture,
            RestrictedAppsRunning: restrictedApps,
            ActivityLog: logs ?? []);
    }

    /// <summary>
    /// Generates a structured Markdown Family Safety Posture Report.
    /// </summary>
    public string GenerateParentalPostureReport(
        ParentalPostureSnapshot snapshot,
        IReadOnlyList<ParentalActivityLogEntry>? logEntries = null)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# Parental Controls & Family Safety Posture Report");
        sb.AppendLine();
        sb.AppendLine($"- **Profile**: `{snapshot.Config.ProfileName}`");
        sb.AppendLine($"- **Assessment Date**: `{snapshot.CapturedAtUtc:yyyy-MM-dd HH:mm:ss} UTC`");
        sb.AppendLine($"- **Master State**: `{(snapshot.Config.Enabled ? "ENABLED" : "DISABLED")}`");
        sb.AppendLine();
        sb.AppendLine("## 1. Screen Time Management");
        sb.AppendLine();
        sb.AppendLine($"- **Schedule Active**: `{(snapshot.Config.ScreenTime.Enabled ? "Yes" : "No")}`");
        sb.AppendLine($"- **Today's Limit**: **{snapshot.ScreenTime.TodayLimitMinutes} minutes** ({(snapshot.CapturedAtUtc.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday ? "Weekend" : "Weekday")})");
        sb.AppendLine($"- **Used Today**: **{snapshot.ScreenTime.TodayUsageMinutes} minutes** ({snapshot.ScreenTime.WarningPercent:F1}%)");
        sb.AppendLine($"- **Remaining**: **{snapshot.ScreenTime.RemainingMinutes} minutes**");
        sb.AppendLine($"- **Bedtime Window**: `{snapshot.Config.ScreenTime.BedtimeStart} - {snapshot.Config.ScreenTime.BedtimeEnd}`");
        sb.AppendLine($"- **Curfew Status**: {(snapshot.ScreenTime.IsWithinCurfew ? "**ACTIVE CURFEW**" : "Open Access")}");
        sb.AppendLine();

        sb.AppendLine("## 2. Web Content Filtering");
        sb.AppendLine();
        var domains = GetDomainsToBlock(snapshot.Config.WebFilter);
        sb.AppendLine($"- **Filtering State**: `{(snapshot.Config.WebFilter.Enabled ? "ENABLED" : "DISABLED")}`");
        sb.AppendLine($"- **Block Adult Content**: `{(snapshot.Config.WebFilter.BlockAdultContent ? "YES" : "NO")}`");
        sb.AppendLine($"- **Block Gambling**: `{(snapshot.Config.WebFilter.BlockGambling ? "YES" : "NO")}`");
        sb.AppendLine($"- **Block Violence**: `{(snapshot.Config.WebFilter.BlockViolence ? "YES" : "NO")}`");
        sb.AppendLine($"- **Block Weapons**: `{(snapshot.Config.WebFilter.BlockWeapons ? "YES" : "NO")}`");
        sb.AppendLine($"- **Block Drugs**: `{(snapshot.Config.WebFilter.BlockDrugs ? "YES" : "NO")}`");
        sb.AppendLine($"- **Total Blocked Domains**: **{domains.Count}**");
        sb.AppendLine($"- **Hosts File Integration**: `{(snapshot.HostsPosture.HasDownpourFilterMarker ? "ACTIVE (" + snapshot.HostsPosture.ActiveBlockedDomainsCount + " entries)" : "NOT APPLIED")}`");
        sb.AppendLine();

        sb.AppendLine("## 3. Application Restrictions");
        sb.AppendLine();
        sb.AppendLine($"- **App Monitoring**: `{(snapshot.Config.AppRestrictions.Enabled ? "ENABLED" : "DISABLED")}`");
        sb.AppendLine($"- **Configured Blocked Apps**: {string.Join(", ", snapshot.Config.AppRestrictions.BlockedExecutableNames)}");
        if (snapshot.RestrictedAppsRunning.Count > 0)
        {
            sb.AppendLine($"> [!WARNING]");
            sb.AppendLine($"> **Active Restricted Apps Detected**: {string.Join(", ", snapshot.RestrictedAppsRunning)}");
        }
        else
        {
            sb.AppendLine("> [!NOTE]");
            sb.AppendLine("> No restricted applications are currently running.");
        }
        sb.AppendLine();

        if (logEntries is { Count: > 0 })
        {
            sb.AppendLine("## 4. Activity & Policy Audit Log");
            sb.AppendLine();
            sb.AppendLine("| Timestamp (UTC) | Category | Severity | Summary |");
            sb.AppendLine("|-----------------|----------|----------|---------|");
            foreach (var log in logEntries)
            {
                sb.AppendLine($"| `{log.TimestampUtc:HH:mm:ss}` | {log.Category} | {log.Severity} | {log.Summary} |");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static bool IsTimeWithinCurfew(TimeSpan currentTime, string startStr, string endStr)
    {
        if (!TimeSpan.TryParseExact(startStr, @"hh\:mm", CultureInfo.InvariantCulture, out var start) ||
            !TimeSpan.TryParseExact(endStr, @"hh\:mm", CultureInfo.InvariantCulture, out var end))
        {
            return false;
        }

        if (start <= end)
        {
            // E.g., 01:00 to 06:00
            return currentTime >= start && currentTime < end;
        }
        else
        {
            // Overnight curfew, e.g., 21:00 to 07:00
            return currentTime >= start || currentTime < end;
        }
    }

    private static string CleanDomain(string raw)
    {
        string d = raw.Trim().ToLowerInvariant();
        if (d.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) d = d[8..];
        if (d.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) d = d[7..];
        int slashIdx = d.IndexOf('/');
        if (slashIdx >= 0) d = d[..slashIdx];
        return d;
    }

    private static string NormalizeExeName(string name)
    {
        string n = name.ToLowerInvariant();
        return n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? n : n + ".exe";
    }

    private ParentalControlsConfig LoadOrCreateDefaultConfig()
    {
        try
        {
            if (File.Exists(_configFilePath))
            {
                string json = File.ReadAllText(_configFilePath);
                var loaded = JsonConvert.DeserializeObject<ParentalControlsConfig>(json);
                if (loaded is not null) return loaded;
            }
        }
        catch
        {
            // Use default on read failure
        }

        return new ParentalControlsConfig(
            Enabled: true,
            ProfileName: "Child Profile",
            ScreenTime: new ScreenTimeSchedule(
                Enabled: true,
                WeekdayLimitMinutes: 120,
                WeekendLimitMinutes: 240,
                BedtimeStart: "21:00",
                BedtimeEnd: "07:00"),
            WebFilter: new WebFilterPolicy(
                Enabled: true,
                BlockAdultContent: true,
                BlockGambling: true,
                BlockViolence: true,
                BlockWeapons: true,
                BlockDrugs: true,
                CustomBlockedDomains: [],
                SafeSearchEnforced: true),
            AppRestrictions: new AppRestrictionPolicy(
                Enabled: true,
                BlockedExecutableNames: ["discord.exe", "steam.exe", "epicgameslauncher.exe", "robloxplayerbeta.exe", "torrent.exe", "utorrent.exe"],
                MonitoredProfileUsername: ""));
    }
}
