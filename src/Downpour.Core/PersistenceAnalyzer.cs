using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>A raw item observed by a collector, before baseline comparison.</summary>
public sealed record PersistenceObservation(string Category, string Location, string Name, string Value, string Technique, string RunAs = "");

/// <summary>Stored per-item baseline state: a value hash, never the value itself.</summary>
public sealed record PersistenceBaselineItem(string ValueSha256, DateTimeOffset? FirstSeenUtc, DateTimeOffset? LastChangedUtc);

public sealed record PersistenceBaseline(int SchemaVersion, DateTimeOffset CreatedAtUtc, IReadOnlyDictionary<string, PersistenceBaselineItem> Items);

/// <summary>
/// Baseline diffing and v29 heuristics from persistence_watchers.py, scheduled_task_monitor.py and
/// wmi_persistence_detector.py. Like v29, heuristics that would be noisy on a clean system (scheduled-task actions
/// and paths) only apply to items that are new or modified since the trust-on-first-use baseline; BYOVD drivers,
/// DLL shadows and WMI command-line/script consumers are reported whenever present, as v29 did.
/// </summary>
public static partial class PersistenceAnalyzer
{
    /// <summary>How long a new or modified item stays highlighted.</summary>
    public static readonly TimeSpan RecentWindow = TimeSpan.FromDays(7);
    public const int MaximumBaselineItems = 8192;

    /// <summary>persistence_watchers.py HIJACKABLE_SYSTEM_DLLS.</summary>
    public static readonly IReadOnlySet<string> HijackableSystemDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "winmm.dll", "dbghelp.dll", "shcore.dll", "uxtheme.dll",
        "dwmapi.dll", "propsys.dll", "linkinfo.dll", "ntlanman.dll",
        "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll",
        "iphlpapi.dll", "winhttp.dll", "secur32.dll", "shell32.dll",
        "wlanapi.dll", "cryptbase.dll", "sfc_os.dll", "profapi.dll",
    };

    /// <summary>persistence_watchers.py BYOVD_BLOCKLIST.</summary>
    public static readonly IReadOnlyDictionary<string, string> ByovdBlocklist = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["gdrv.sys"] = "Gigabyte GDRV (CVE-2018-19320)",
        ["dbutil_2_3.sys"] = "Dell DBUtil (CVE-2021-21551)",
        ["rtcore64.sys"] = "MSI Afterburner RTCore64",
        ["iqvw64e.sys"] = "Intel IQVW64E (CVE-2015-2291)",
        ["kprocesshacker.sys"] = "KProcessHacker",
        ["ntiolib.sys"] = "MSI NTIOLib",
        ["msio64.sys"] = "MSI MSIO64",
        ["asrdrv.sys"] = "ASRock ASRDRV (CVE-2019-16902)",
        ["glckio2.sys"] = "GIGABYTE GLCKIO2",
        ["winio64.sys"] = "WinIo64",
    };

    /// <summary>wmi_persistence_detector.py LEGITIMATE_FILTERS.</summary>
    public static readonly IReadOnlySet<string> LegitimateWmiFilters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "BVTFilter", "SCM Event Log Filter", "__InstanceCreationEvent" };

    public static string Key(PersistenceObservation o) => $"{o.Category}|{o.Location}|{o.Name}";

    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Compares observations to the baseline and returns the entries plus the updated baseline.</summary>
    public static (IReadOnlyList<PersistenceEntry> Entries, PersistenceBaseline Baseline, bool FirstBaseline) Compare(
        IReadOnlyList<PersistenceObservation> observations, PersistenceBaseline? baseline, DateTimeOffset now)
    {
        var first = baseline is null;
        var created = baseline?.CreatedAtUtc ?? now;
        var known = baseline?.Items ?? new Dictionary<string, PersistenceBaselineItem>();
        var updated = new Dictionary<string, PersistenceBaselineItem>(StringComparer.Ordinal);
        var entries = new List<PersistenceEntry>(observations.Count);

        foreach (var observation in observations)
        {
            var key = Key(observation);
            if (updated.ContainsKey(key)) continue;
            var hash = Hash(observation.Value);
            PersistenceBaselineItem item;
            if (first)
                item = new(hash, null, null);
            else if (!known.TryGetValue(key, out var previous))
                item = new(hash, now, now);
            else if (!previous.ValueSha256.Equals(hash, StringComparison.Ordinal))
                item = previous with { ValueSha256 = hash, LastChangedUtc = now };
            else
                item = previous;
            if (updated.Count < MaximumBaselineItems) updated[key] = item;

            var (change, changedAt) = ClassifyChange(item, now);
            // v29 applied these heuristics to new items only; on baseline items they mislabel legitimate software
            // (for example GoogleUpdateTaskMachineUA matches v29's ^GoogleUpdate[A-Z]{4,} pattern).
            IReadOnlyList<string> indicators = change == PersistenceChanges.Baseline ? [] : Indicators(observation);
            entries.Add(new PersistenceEntry(observation.Category, observation.Location, observation.Name, observation.Value,
                observation.Technique, change, changedAt, indicators));
        }
        return (entries, new PersistenceBaseline(1, created, updated), first);
    }

    internal static (string Change, DateTimeOffset? At) ClassifyChange(PersistenceBaselineItem item, DateTimeOffset now)
    {
        if (item.FirstSeenUtc is { } firstSeen && now - firstSeen <= RecentWindow && item.LastChangedUtc == firstSeen)
            return (PersistenceChanges.New, firstSeen);
        if (item.LastChangedUtc is { } changed && now - changed <= RecentWindow)
            return (item.FirstSeenUtc == changed ? PersistenceChanges.New : PersistenceChanges.Modified, changed);
        return (PersistenceChanges.Baseline, null);
    }

    /// <summary>Informational v29 indicators for display; findings come from <see cref="Findings"/>.</summary>
    public static IReadOnlyList<string> Indicators(PersistenceObservation o)
    {
        var indicators = new List<string>();
        if (o.Category == PersistenceCategories.ScheduledTask)
        {
            if (MalwareTaskName().IsMatch(LeafName(o.Name))) indicators.Add("Name matches a known malware task pattern");
            if (SuspiciousTaskAction().IsMatch(o.Value)) indicators.Add("Action uses a script host or LOLBin");
            if (SuspiciousTaskPath().IsMatch(o.Value)) indicators.Add("Runs from a user-writable path");
            if (IsPrivilegedAccount(o.RunAs)) indicators.Add($"Runs as {o.RunAs}");
        }
        if (o.Category is PersistenceCategories.RegistryRun or PersistenceCategories.StartupFolder && SuspiciousTaskAction().IsMatch(o.Value))
            indicators.Add("Starts a script host or LOLBin");
        return indicators;
    }

    public static IReadOnlyList<PersistenceFinding> Findings(IReadOnlyList<PersistenceEntry> entries, IReadOnlyList<PersistenceObservation> observations)
    {
        var runAs = observations.GroupBy(Key).ToDictionary(group => group.Key, group => group.First().RunAs, StringComparer.Ordinal);
        var findings = new List<PersistenceFinding>();
        foreach (var entry in entries)
        {
            var recent = entry.Change != PersistenceChanges.Baseline;
            var verb = entry.Change == PersistenceChanges.Modified ? "modified" : "new";
            switch (entry.Category)
            {
                case PersistenceCategories.DriverFile when ByovdBlocklist.TryGetValue(entry.Name, out var driver):
                    findings.Add(new("CRITICAL", "T1068", entry.Category, $"Known-vulnerable driver present (BYOVD): {entry.Name} ({driver})", entry.Value));
                    break;
                case PersistenceCategories.DriverFile when recent:
                    findings.Add(new("MEDIUM", "T1068", entry.Category, $"New kernel driver file: {entry.Name}", entry.Value));
                    break;
                case PersistenceCategories.DllShadow:
                    findings.Add(new("HIGH", "T1574.001", entry.Category, $"{entry.Name} shadows a system DLL in a PATH folder standard users can write to", entry.Value));
                    break;
                case PersistenceCategories.WmiSubscription when entry.Name.StartsWith("CommandLineEventConsumer:", StringComparison.Ordinal)
                                                             || entry.Name.StartsWith("ActiveScriptEventConsumer:", StringComparison.Ordinal):
                    findings.Add(new("CRITICAL", "T1546.003", entry.Category, $"WMI event consumer can run code: {entry.Name}", entry.Value));
                    break;
                case PersistenceCategories.WmiSubscription when recent && entry.Name.StartsWith("__EventFilter:", StringComparison.Ordinal)
                                                             && !LegitimateWmiFilters.Contains(entry.Name["__EventFilter:".Length..]):
                    findings.Add(new("HIGH", "T1546.003", entry.Category, $"New WMI event filter: {entry.Name}", entry.Value));
                    break;
                case PersistenceCategories.RegistryRun or PersistenceCategories.Winlogon when recent:
                    findings.Add(new("HIGH", entry.Change == PersistenceChanges.Modified ? "T1574.011" : entry.Technique, entry.Category,
                        $"Autostart value {verb}: {entry.Location}\\{entry.Name}", entry.Value));
                    break;
                case PersistenceCategories.StartupFolder when recent:
                    findings.Add(new("HIGH", entry.Technique, entry.Category, $"Startup folder item {verb}: {entry.Name}", entry.Value));
                    break;
                case PersistenceCategories.ScheduledTask when recent:
                    findings.Add(TaskFinding(entry, runAs.GetValueOrDefault($"{entry.Category}|{entry.Location}|{entry.Name}", ""), verb));
                    break;
            }
        }
        return findings.Select(finding => finding with { Summary = Bound(finding.Summary), Indicator = Bound(finding.Indicator) }).ToArray();
    }

    private static string Bound(string value) => value.Length <= 1000 ? value : value[..1000];

    /// <summary>scheduled_task_monitor.py _check_new_tasks severity for a new task (highest applicable).</summary>
    private static PersistenceFinding TaskFinding(PersistenceEntry entry, string runAs, string verb)
    {
        var severity = MalwareTaskName().IsMatch(LeafName(entry.Name)) ? "CRITICAL"
            : SuspiciousTaskAction().IsMatch(entry.Value) || SuspiciousTaskPath().IsMatch(entry.Value) || IsPrivilegedAccount(runAs) ? "HIGH"
            : "MEDIUM";
        var reasons = entry.Indicators.Count == 0 ? "" : $" ({string.Join("; ", entry.Indicators)})";
        return new(severity, "T1053.005", entry.Category, $"Scheduled task {verb}: {entry.Name}{reasons}", entry.Value);
    }

    private static string LeafName(string taskPath)
    {
        var slash = taskPath.LastIndexOf('\\');
        return slash >= 0 ? taskPath[(slash + 1)..] : taskPath;
    }

    private static bool IsPrivilegedAccount(string runAs) =>
        runAs.Trim().ToUpperInvariant() is "SYSTEM" or "NT AUTHORITY\\SYSTEM" or "LOCAL SERVICE" or "S-1-5-18" or "S-1-5-19";

    [GeneratedRegex(@"powershell|cmd\.exe\s+/c|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SuspiciousTaskAction();

    [GeneratedRegex(@"\\Users\\.*\\AppData|\\Temp\\|\\ProgramData\\|\\Public\\|\\Downloads\\|\\Desktop\\|%APPDATA%|%TEMP%|%USERPROFILE%", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SuspiciousTaskPath();

    [GeneratedRegex(@"^WindowsUpdate\d{3,}$|^SystemCheck\d+$|^MicrosoftUpdate|^Updater[A-Z]|^GoogleUpdate[A-Z]{4,}|^[a-f0-9]{32}$|^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MalwareTaskName();
}
