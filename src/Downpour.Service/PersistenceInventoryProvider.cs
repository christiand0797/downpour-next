using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

/// <summary>
/// Read-only autostart and persistence inventory (v29 persistence_watchers, scheduled_task_monitor and
/// wmi_persistence_detector). Live values are displayed but only their SHA-256 is persisted in the baseline.
/// </summary>
public sealed class PersistenceInventoryProvider(string baselinePath)
{
    internal const int MaximumEntries = 4096;
    private const int MaximumText = 512;
    private const int MaximumTasks = 4096;
    private const long MaximumBaselineBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions BaselineJson = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();

    public static PersistenceInventoryProvider CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var path = Path.Combine(root, "persistence-baseline.v1.json");
        SecureJournalDirectory.RestrictExistingFile(path);
        return new PersistenceInventoryProvider(path);
    }

    private static readonly (RegistryHive Hive, string HiveName, string Path)[] RunKeys =
    [
        (RegistryHive.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        // Not in v29: 32-bit autostart keys on 64-bit Windows are a separate location.
        (RegistryHive.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];

    /// <summary>
    /// v29 diffed every Winlogon value, which alerts on routine changes such as LastUsedUsername. Only the values
    /// that launch code (T1547.004) are watched here.
    /// </summary>
    internal static readonly string[] WinlogonPersistenceValues = ["Shell", "Userinit", "Taskman", "AppSetup", "GinaDLL", "VmApplet"];

    public PersistenceSnapshot Capture()
    {
        var warnings = new List<string>();
        var status = new List<string>();
        var observations = new List<PersistenceObservation>();

        ReadRegistry(observations, status);
        ReadStartupFolders(observations, status);
        ReadScheduledTasks(observations, status, warnings);
        ReadWmiSubscriptions(observations, status);
        ReadDllShadows(observations, status);
        var (driverObservations, driverStatus) = ReadDriverFiles();
        status.Add(driverStatus);

        // Drivers are baselined in full but only noteworthy ones are listed, to keep ~500 inbox drivers out of the view.
        var all = observations.Concat(driverObservations).Take(PersistenceAnalyzer.MaximumBaselineItems).ToArray();
        if (observations.Count + driverObservations.Count > all.Length)
            warnings.Add($"Inventory limited to {PersistenceAnalyzer.MaximumBaselineItems:N0} items.");

        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var baseline = LoadBaseline(warnings);
            var (entries, updated, first) = PersistenceAnalyzer.Compare(all, baseline, now);
            SaveBaseline(updated, warnings);
            var findings = PersistenceAnalyzer.Findings(entries, all);
            var visible = entries
                .Where(entry => entry.Category != PersistenceCategories.DriverFile
                    || entry.Change != PersistenceChanges.Baseline
                    || PersistenceAnalyzer.ByovdBlocklist.ContainsKey(entry.Name))
                .Take(MaximumEntries)
                .ToArray();
            return new PersistenceSnapshot(1, now, updated.CreatedAtUtc, first, visible, findings.Take(256).ToArray(), status, warnings);
        }
    }

    private static void ReadRegistry(List<PersistenceObservation> observations, List<string> status)
    {
        var read = 0;
        var denied = 0;
        foreach (var (hive, hiveName, path) in RunKeys)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var key = root.OpenSubKey(path);
                if (key is null) continue;
                foreach (var name in key.GetValueNames())
                {
                    if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not { } value) continue;
                    observations.Add(new(PersistenceCategories.RegistryRun, $"{hiveName}\\{path}", Text(name.Length == 0 ? "(Default)" : name), Text(value.ToString() ?? ""), "T1547.001"));
                    read++;
                }
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                denied++;
            }
        }

        foreach (var (hive, hiveName) in new[] { (RegistryHive.LocalMachine, "HKLM"), (RegistryHive.CurrentUser, "HKCU") })
        {
            const string winlogon = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var key = root.OpenSubKey(winlogon);
                if (key is null) continue;
                foreach (var name in WinlogonPersistenceValues)
                {
                    if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not { } value) continue;
                    var text = value is string[] parts ? string.Join(" ", parts) : value.ToString() ?? "";
                    observations.Add(new(PersistenceCategories.Winlogon, $"{hiveName}\\{winlogon}", name, Text(text), "T1547.004"));
                    read++;
                }
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                denied++;
            }
        }
        status.Add(denied == 0 ? $"Registry autostart: {read} values" : $"Registry autostart: {read} values, {denied} keys not readable");
    }

    private static void ReadStartupFolders(List<PersistenceObservation> observations, List<string> status)
    {
        var count = 0;
        foreach (var (folder, label) in new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Current user"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "All users"),
        })
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(folder).Take(512))
                {
                    var name = Path.GetFileName(file);
                    if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    observations.Add(new(PersistenceCategories.StartupFolder, $"{label} startup", Text(name), Text(file), "T1547.001"));
                    count++;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                // Folder not readable; reported through the count.
            }
        }
        status.Add($"Startup folders: {count} items");
    }

    private static void ReadScheduledTasks(List<PersistenceObservation> observations, List<string> status, List<string> warnings)
    {
        var serviceType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: false);
        if (serviceType is null)
        {
            status.Add("Scheduled tasks: Task Scheduler is unavailable");
            return;
        }
        object? schedulerObject = null;
        var count = 0;
        var deniedFolders = 0;
        try
        {
            schedulerObject = Activator.CreateInstance(serviceType);
            dynamic scheduler = schedulerObject!;
            scheduler.Connect();
            var pending = new Stack<object>();
            pending.Push(scheduler.GetFolder("\\"));
            while (pending.Count > 0 && count < MaximumTasks)
            {
                dynamic folder = pending.Pop();
                try
                {
                    foreach (var child in (System.Collections.IEnumerable)folder.GetFolders(0)) pending.Push(child);
                    // 1 = TASK_ENUM_HIDDEN, so hidden tasks (a common persistence trick) are included.
                    foreach (dynamic task in (System.Collections.IEnumerable)folder.GetTasks(1))
                    {
                        if (count >= MaximumTasks) break;
                        try
                        {
                            string taskPath = task.Path;
                            dynamic definition = task.Definition;
                            string runAs = "";
                            try { runAs = (string)definition.Principal.UserId ?? ""; } catch (COMException) { }
                            var actions = new List<string>();
                            foreach (dynamic action in (System.Collections.IEnumerable)definition.Actions)
                            {
                                int type = action.Type;
                                actions.Add(type switch
                                {
                                    0 => $"{(string)action.Path} {(string)action.Arguments}".Trim(),
                                    5 => $"COM handler {(string)action.ClassId}",
                                    _ => $"Action type {type}"
                                });
                            }
                            var enabled = (bool)task.Enabled ? "" : " [disabled]";
                            observations.Add(new(PersistenceCategories.ScheduledTask, Text((string)folder.Path), Text(taskPath),
                                Text(string.Join(" ; ", actions) + enabled), "T1053.005", Text(runAs)));
                            count++;
                        }
                        catch (COMException)
                        {
                            // Task definition not readable by this user.
                        }
                    }
                }
                catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
                {
                    deniedFolders++;
                }
            }
            status.Add(deniedFolders == 0 ? $"Scheduled tasks: {count}" : $"Scheduled tasks: {count}, {deniedFolders} folders not readable");
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            status.Add("Scheduled tasks: could not be read");
            warnings.Add($"Task Scheduler query failed ({ex.GetType().Name}).");
        }
        finally
        {
            if (schedulerObject is not null && Marshal.IsComObject(schedulerObject)) Marshal.FinalReleaseComObject(schedulerObject);
        }
    }

    private static void ReadWmiSubscriptions(List<PersistenceObservation> observations, List<string> status)
    {
        var count = 0;
        try
        {
            var scope = new ManagementScope(@"root\subscription");
            var options = new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(5), ReturnImmediately = false };
            (string Class, string Fields, Func<ManagementBaseObject, string> Describe)[] queries =
            [
                ("__EventFilter", "Name, Query", o => $"{o["Query"]}"),
                ("CommandLineEventConsumer", "Name, CommandLineTemplate, ExecutablePath", o => $"{o["ExecutablePath"]} {o["CommandLineTemplate"]}".Trim()),
                ("ActiveScriptEventConsumer", "Name, ScriptingEngine, ScriptFileName", o => $"{o["ScriptingEngine"]} {o["ScriptFileName"]}".Trim()),
                ("__FilterToConsumerBinding", "Filter, Consumer", o => $"{o["Filter"]} -> {o["Consumer"]}"),
            ];
            foreach (var (className, fields, describe) in queries)
            {
                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT {fields} FROM {className}"), options);
                foreach (var item in searcher.Get())
                {
                    using (item)
                    {
                        var name = className == "__FilterToConsumerBinding" ? $"binding {count}" : item["Name"]?.ToString() ?? "(unnamed)";
                        var value = describe(item);
                        if (className == "__FilterToConsumerBinding") name = $"binding:{Text(value)}";
                        observations.Add(new(PersistenceCategories.WmiSubscription, @"root\subscription", Text($"{className}:{name}"), Text(value), "T1546.003"));
                        count++;
                    }
                }
            }
            status.Add($"WMI subscriptions: {count} objects");
        }
        catch (Exception ex) when (ex is ManagementException { ErrorCode: ManagementStatus.AccessDenied } or UnauthorizedAccessException)
        {
            status.Add("WMI subscriptions: access denied (requires administrator)");
        }
        catch (Exception ex) when (ex is ManagementException or COMException or TimeoutException)
        {
            status.Add($"WMI subscriptions: unavailable ({ex.GetType().Name})");
        }
    }

    private static void ReadDllShadows(List<PersistenceObservation> observations, List<string> status)
    {
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var directories = (Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) + ";"
                           + Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User))
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(directory => Environment.ExpandEnvironmentVariables(directory.Trim('"')))
            .Where(directory => directory.Length > 0 && Path.IsPathFullyQualified(directory))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(256)
            .ToArray();
        var writable = 0;
        foreach (var directory in directories)
        {
            if (directory.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase) || !Directory.Exists(directory)) continue;
            if (!IsWritableByStandardUsers(directory)) continue;
            writable++;
            try
            {
                foreach (var file in Directory.EnumerateFiles(directory, "*.dll"))
                {
                    var name = Path.GetFileName(file);
                    if (PersistenceAnalyzer.HijackableSystemDlls.Contains(name))
                        observations.Add(new(PersistenceCategories.DllShadow, Text(directory), name, Text(file), "T1574.001"));
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                // Unreadable directory.
            }
        }
        status.Add($"PATH folders writable by standard users: {writable} of {directories.Length}");
    }

    /// <summary>
    /// True when the directory ACL lets ordinary users plant files: an allow rule granting CreateFiles/WriteData to
    /// Everyone, Authenticated Users, Users, INTERACTIVE or the current user, with no matching deny. This replaces
    /// v29's os.access(W_OK), which on Windows only checks the read-only attribute.
    /// </summary>
    internal static bool IsWritableByStandardUsers(string directory)
    {
        try
        {
            var current = WindowsIdentity.GetCurrent().User;
            var broad = new HashSet<SecurityIdentifier>
            {
                new(WellKnownSidType.WorldSid, null),
                new(WellKnownSidType.AuthenticatedUserSid, null),
                new(WellKnownSidType.BuiltinUsersSid, null),
                new(WellKnownSidType.InteractiveSid, null),
            };
            if (current is not null) broad.Add(current);
            var rules = new DirectoryInfo(directory).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
            const FileSystemRights plant = FileSystemRights.CreateFiles | FileSystemRights.WriteData;
            bool allowed = false, denied = false;
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.IdentityReference is not SecurityIdentifier sid || !broad.Contains(sid) || (rule.FileSystemRights & plant) == 0) continue;
                if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
                if (rule.AccessControlType == AccessControlType.Deny) denied = true; else allowed = true;
            }
            return allowed && !denied;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException or SystemException)
        {
            return false;
        }
    }

    private static (IReadOnlyList<PersistenceObservation>, string) ReadDriverFiles()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
        var list = new List<PersistenceObservation>();
        try
        {
            foreach (var file in new DirectoryInfo(directory).EnumerateFiles("*.sys").Take(4096))
            {
                // Fingerprint with size and write time so a replaced driver shows as modified, not just a new name.
                list.Add(new(PersistenceCategories.DriverFile, directory, file.Name.ToLowerInvariant(),
                    $"{file.FullName} ({file.Length:N0} bytes, written {file.LastWriteTimeUtc:yyyy-MM-dd HH:mm} UTC)", "T1068"));
            }
            return (list, $"Driver files: {list.Count}");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return (list, "Driver files: not readable");
        }
    }

    private PersistenceBaseline? LoadBaseline(List<string> warnings)
    {
        try
        {
            var info = new FileInfo(baselinePath);
            if (!info.Exists) return null;
            if (info.Length > MaximumBaselineBytes || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                warnings.Add("The persistence baseline was invalid and has been recreated; changes before now are not highlighted.");
                return null;
            }
            var baseline = JsonSerializer.Deserialize<PersistenceBaseline>(File.ReadAllBytes(baselinePath), BaselineJson);
            if (baseline is { SchemaVersion: 1, Items: not null } && baseline.Items.Count <= PersistenceAnalyzer.MaximumBaselineItems
                && baseline.Items.All(item => item.Key.Length <= 4096 && item.Value is { ValueSha256.Length: 64 }))
                return baseline;
            warnings.Add("The persistence baseline was invalid and has been recreated; changes before now are not highlighted.");
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            warnings.Add("The persistence baseline could not be read and has been recreated; changes before now are not highlighted.");
            return null;
        }
    }

    private void SaveBaseline(PersistenceBaseline baseline, List<string> warnings)
    {
        var temporary = baselinePath + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(baseline, BaselineJson));
            File.Move(temporary, baselinePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"The persistence baseline could not be saved ({ex.GetType().Name}); new items will be re-reported.");
            try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private static string Text(string value) => value.Length <= MaximumText ? value : value[..MaximumText];
}
