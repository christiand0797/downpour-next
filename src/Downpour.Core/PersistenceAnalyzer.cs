using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>A raw item observed by a collector, before baseline comparison.</summary>
public sealed record PersistenceObservation(string Category, string Location, string Name, string Value, string Technique, string RunAs = "");

/// <summary>Stored per-item baseline state: a value hash, never the value itself.</summary>
public sealed record PersistenceBaselineItem(string ValueSha256, DateTimeOffset? FirstSeenUtc, DateTimeOffset? LastChangedUtc);

/// <summary>
/// Authenticode result for the file an autostart entry or driver points at. <c>Signed</c> is null when the file could
/// not be checked; <c>Microsoft</c> is true only for Microsoft's own production signers.
/// </summary>
public sealed record PersistenceSignature(bool? Signed, string? Signer, bool Microsoft);

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

    /// <summary>
    /// Builds findings. <paramref name="signer"/> (optional) verifies the file an entry launches; it is only called for
    /// entries that would otherwise raise a finding, so signed vendor software (for example Microsoft Edge's
    /// msedge_cleanup RunOnce value) is reported at LOW instead of HIGH, and a signed vendor driver on the BYOVD list is
    /// reported as legitimate but vulnerable rather than CRITICAL. Without a signer the v29 severities apply.
    /// </summary>
    public static IReadOnlyList<PersistenceFinding> Findings(IReadOnlyList<PersistenceEntry> entries, IReadOnlyList<PersistenceObservation> observations,
        Func<PersistenceEntry, PersistenceSignature?>? signer = null)
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
                    findings.Add(ByovdFinding(entry, driver, signer?.Invoke(entry)));
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
                {
                    var (severity, reason) = AutostartSeverity(entry, signer);
                    findings.Add(new(severity, entry.Change == PersistenceChanges.Modified ? "T1574.011" : entry.Technique, entry.Category,
                        $"Autostart value {verb}: {entry.Location}\\{entry.Name}{reason}", entry.Value));
                    break;
                }
                case PersistenceCategories.StartupFolder when recent:
                {
                    var (severity, reason) = AutostartSeverity(entry, signer);
                    findings.Add(new(severity, entry.Technique, entry.Category, $"Startup folder item {verb}: {entry.Name}{reason}", entry.Value));
                    break;
                }
                case PersistenceCategories.ScheduledTask when recent:
                    findings.Add(TaskFinding(entry, runAs.GetValueOrDefault($"{entry.Category}|{entry.Location}|{entry.Name}", ""), verb));
                    break;
            }
        }
        return findings.Select(finding => finding with { Summary = Bound(finding.Summary), Indicator = Bound(finding.Indicator) }).ToArray();
    }

    private static string Bound(string value) => value.Length <= 1000 ? value : value[..1000];

    private static PersistenceFinding ByovdFinding(PersistenceEntry entry, string driver, PersistenceSignature? signature)
    {
        var summary = $"Known-vulnerable driver present (BYOVD): {entry.Name} ({driver})";
        return signature?.Signed switch
        {
            // Matches ThreatVerdictEngine's "legitimate but vulnerable" verdict: a vendor tool installed it, but an
            // attacker with admin rights could load it to reach the kernel.
            true => new("MEDIUM", "T1068", entry.Category,
                $"{summary}: legitimate but vulnerable, signed by {SignerDisplay(signature.Signer)}. Update or uninstall the vendor tool if unused", entry.Value),
            false => new("CRITICAL", "T1068", entry.Category, $"{summary}: not validly signed", entry.Value),
            _ => new("CRITICAL", "T1068", entry.Category, summary, entry.Value),
        };
    }

    /// <summary>
    /// Severity for a new or changed Run/RunOnce, Winlogon or Startup item. Script hosts and LOLBins stay HIGH even
    /// though they are Microsoft-signed; a signed target in a protected folder drops to LOW; a signed target in a
    /// user-writable folder is MEDIUM; unsigned or unverifiable targets stay HIGH.
    /// </summary>
    internal static (string Severity, string Reason) AutostartSeverity(PersistenceEntry entry, Func<PersistenceEntry, PersistenceSignature?>? signer)
    {
        if (SuspiciousTaskAction().IsMatch(entry.Value)) return ("HIGH", " (starts a script host or LOLBin)");
        if (signer?.Invoke(entry) is not { } signature) return ("HIGH", "");
        var userWritable = SuspiciousTaskPath().IsMatch(LaunchTarget(entry) ?? entry.Value);
        return signature.Signed switch
        {
            true when !userWritable => ("LOW", $" (signed by {SignerDisplay(signature.Signer)})"),
            true => ("MEDIUM", $" (signed by {SignerDisplay(signature.Signer)}, but runs from a user-writable folder)"),
            false => ("HIGH", " (target is not validly signed)"),
            _ => ("HIGH", ""),
        };
    }

    /// <summary>
    /// The file an entry launches, unexpanded: the executable at the start of a Run/Winlogon command line, the startup
    /// folder file, or the driver file. Null for entries without a file target.
    /// </summary>
    public static string? LaunchTarget(PersistenceEntry entry) => entry.Category switch
    {
        PersistenceCategories.RegistryRun or PersistenceCategories.Winlogon => CommandTarget(entry.Value),
        PersistenceCategories.StartupFolder => entry.Value.Length == 0 ? null : entry.Value,
        PersistenceCategories.DriverFile => entry.Location.Length == 0 ? null : $"{entry.Location.TrimEnd('\\')}\\{entry.Name}",
        _ => null,
    };

    /// <summary>The executable at the start of a command line: a quoted path, an unquoted path ending in .exe, or the first token.</summary>
    public static string? CommandTarget(string command)
    {
        var text = command.Trim();
        if (text.Length == 0) return null;
        if (text[0] == '"')
        {
            var close = text.IndexOf('"', 1);
            var quoted = (close > 1 ? text[1..close] : text[1..]).Trim();
            return quoted.Length == 0 ? null : quoted;
        }
        var match = UnquotedExecutable().Match(text);
        if (match.Success) return match.Value;
        var end = text.IndexOfAny([' ', ',']);
        return end > 0 ? text[..end] : text;
    }

    /// <summary>Common name from a certificate subject such as "CN=Vendor, O=Vendor, C=US"; plain names pass through.</summary>
    public static string SignerDisplay(string? signer)
    {
        if (string.IsNullOrWhiteSpace(signer)) return "a trusted publisher";
        var index = signer.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
        if (index < 0) return Shorten(signer.Trim(), 120);
        var value = signer[(index + 3)..];
        if (value.StartsWith('"'))
        {
            var close = value.IndexOf('"', 1);
            value = close > 0 ? value[1..close] : value[1..];
        }
        else
        {
            value = value.Split(',')[0];
        }
        return Shorten(value.Trim(), 120);
    }

    private static string Shorten(string value, int length) => value.Length <= length ? value : value[..length];

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

    [GeneratedRegex(@"^.+?\.exe(?=$|[\s,])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnquotedExecutable();

    [GeneratedRegex(@"^WindowsUpdate\d{3,}$|^SystemCheck\d+$|^MicrosoftUpdate|^Updater[A-Z]|^GoogleUpdate[A-Z]{4,}|^[a-f0-9]{32}$|^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MalwareTaskName();
}
