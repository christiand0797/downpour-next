using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

/// <summary>
/// Read-only autostart and persistence inventory (v29 persistence_watchers, scheduled_task_monitor and
/// wmi_persistence_detector). Live values are displayed but only their SHA-256 is persisted in the baseline.
/// </summary>
public sealed class PersistenceInventoryProvider(string baselinePath, FileSignatureChecker? signatures = null)
{
    internal const int MaximumEntries = 4096;
    private const int MaximumText = 512;
    private const int MaximumTasks = 4096;
    private const long MaximumBaselineBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions BaselineJson = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();

    public static PersistenceInventoryProvider CreateForCurrentUser(FileSignatureChecker? signatures = null)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var path = Path.Combine(root, "persistence-baseline.v1.json");
        SecureJournalDirectory.RestrictExistingFile(path);
        return new PersistenceInventoryProvider(path, signatures);
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
        ReadLocalAccounts(observations, status, warnings);
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
            var findings = PersistenceAnalyzer.Findings(entries, all, Signature);
            var visible = entries
                .Where(entry => entry.Category != PersistenceCategories.DriverFile
                    || entry.Change != PersistenceChanges.Baseline
                    || PersistenceAnalyzer.ByovdBlocklist.ContainsKey(entry.Name))
                .Take(MaximumEntries)
                .ToArray();
            return new PersistenceSnapshot(1, now, updated.CreatedAtUtc, first, visible, findings.Take(256).ToArray(), status, warnings);
        }
    }

    /// <summary>
    /// Authenticode check of the file an autostart entry or driver points at. Only fully qualified local paths (after
    /// environment expansion, or a bare name found in the Windows or System32 folder) are opened; network paths and
    /// anything that cannot be read return null so the stricter default severity applies.
    /// </summary>
    private PersistenceSignature? Signature(PersistenceEntry entry)
    {
        if (signatures is null || ResolveTarget(PersistenceAnalyzer.LaunchTarget(entry)) is not { } path) return null;
        return signatures.Check(path);
    }

    internal static string? ResolveTarget(string? target)
    {
        if (string.IsNullOrWhiteSpace(target) || target.Length > 1024) return null;
        try
        {
            var expanded = Environment.ExpandEnvironmentVariables(target.Trim());
            if (expanded.StartsWith(@"\\", StringComparison.Ordinal) || expanded.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return null;
            if (!Path.IsPathFullyQualified(expanded))
            {
                if (expanded.Contains('\\') || expanded.Contains('/')) return null;
                var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
                expanded = new[] { Path.Combine(system, expanded), Path.Combine(windows, expanded) }.FirstOrDefault(File.Exists) ?? "";
                if (expanded.Length == 0) return null;
            }
            var full = Path.GetFullPath(expanded);
            return File.Exists(full) ? full : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException or UnauthorizedAccessException or SecurityException)
        {
            return null;
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
                                Text(string.Join(" ; ", actions) + enabled), "T1053.005", Text(runAs),
                                DescribeTask(task, definition, runAs)));
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

    /// <summary>
    /// Read-only metadata that makes a scheduled task reviewable without opening Task Scheduler. Every property is
    /// optional in practice: a task whose principal or triggers this account cannot read still appears with its action
    /// and state, and the unreadable parts stay blank instead of becoming a guess.
    /// </summary>
    private static PersistenceTaskDetail? DescribeTask(dynamic task, dynamic definition, string runAs)
    {
        try
        {
            var state = ((int)task.State) switch
            {
                1 => "Disabled",
                2 => "Queued",
                3 => "Ready",
                4 => "Running",
                _ => "Unknown",
            };

            var runLevel = "Unknown";
            try { runLevel = (int)definition.Principal.RunLevel == 1 ? "Highest" : "Least privilege"; }
            catch (Exception ex) when (OptionalTaskDetailException(ex)) { }

            var author = "";
            try { author = (string?)definition.RegistrationInfo.Author ?? ""; }
            catch (Exception ex) when (OptionalTaskDetailException(ex)) { }

            var hidden = false;
            try { hidden = (bool)task.Hidden; }
            catch (Exception ex) when (OptionalTaskDetailException(ex)) { }

            var triggers = new List<string>();
            try
            {
                foreach (dynamic trigger in (System.Collections.IEnumerable)definition.Triggers)
                {
                    if (triggers.Count >= 8) break;
                    try
                    {
                        var type = ((int)trigger.Type) switch
                        {
                            1 => "Event",
                            2 => "Time",
                            3 => "Daily",
                            4 => "Weekly",
                            5 => "Monthly",
                            6 => "Monthly day-of-week",
                            7 => "Idle",
                            8 => "At registration",
                            9 => "At boot",
                            10 => "At logon",
                            11 => "Session change",
                            12 => "Custom",
                            _ => "Unknown trigger",
                        };
                        var enabled = (bool)trigger.Enabled ? "" : " (disabled)";
                        var start = "";
                        try
                        {
                            DateTime boundary = trigger.StartBoundary;
                            if (boundary.Year > 1900) start = $" from {boundary:yyyy-MM-dd HH:mm}";
                        }
                        catch (Exception ex) when (OptionalTaskDetailException(ex)) { }
                        triggers.Add(Text($"{type}{start}{enabled}"));
                    }
                    catch (Exception ex) when (OptionalTaskDetailException(ex)) { }
                }
            }
            catch (Exception ex) when (OptionalTaskDetailException(ex)) { }

            DateTimeOffset? lastRun = null;
            int? lastResult = null;
            try
            {
                DateTime value = task.LastRunTime;
                if (value.Year > 1900)
                {
                    lastRun = LocalTaskTime(value);
                    lastResult = (int)task.LastTaskResult;
                }
            }
            catch (Exception ex) when (OptionalTaskDetailException(ex)) { }

            DateTimeOffset? nextRun = null;
            try
            {
                DateTime value = task.NextRunTime;
                if (value.Year > 1900) nextRun = LocalTaskTime(value);
            }
            catch (Exception ex) when (OptionalTaskDetailException(ex)) { }

            return new PersistenceTaskDetail(state, Text(runAs), runLevel, Text(author), hidden, triggers, lastRun, nextRun, lastResult);
        }
        catch (Exception ex) when (OptionalTaskDetailException(ex))
        {
            return null;
        }
    }

    /// <summary>Task Scheduler returns local wall-clock times without a kind.</summary>
    private static DateTimeOffset LocalTaskTime(DateTime value) => new(DateTime.SpecifyKind(value, DateTimeKind.Local));

    private static bool OptionalTaskDetailException(Exception ex) =>
        ex is COMException or InvalidCastException or ArgumentException or UnauthorizedAccessException
            or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException;

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
    /// Local user accounts and who is in the built-in Administrators group. Both are ordinary unelevated queries, so this
    /// needs no policy or privilege. Only the stable attributes (enabled or disabled, administrator or not) enter the
    /// baselined value: a last-logon time would make every sign-in look like a modification and would record user
    /// activity the product deliberately does not collect.
    /// </summary>
    private static void ReadLocalAccounts(List<PersistenceObservation> observations, List<string> status, List<string> warnings)
    {
        var accounts = EnumerateLocalAccounts(warnings);
        var group = AdministratorsGroupName();
        var rows = accounts.Select(account => (account.Name, account.Disabled, Admin: IsAdministrator(account.Name, group))).ToArray();
        foreach (var row in rows)
        {
            observations.Add(new(PersistenceCategories.LocalAccount, "Local users", Text(row.Name),
                $"{(row.Disabled ? "disabled" : "enabled")}, {(row.Admin ? "administrator" : "standard user")}", "T1136.001"));
        }
        status.Add($"Local accounts: {rows.Length}, in Administrators: {rows.Count(row => row.Admin)}");
    }

    private const int FilterNormalAccount = 0x0002;
    private const int UfAccountDisable = 0x0002;
    private const int MaximumLocalAccounts = 256;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        public string Name;
        public string Password;
        public int PasswordAge;
        public int Privilege;
        public string HomeDirectory;
        public string Comment;
        public int Flags;
        public string ScriptPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LocalGroupUsersInfo0
    {
        public string Name;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserEnum(string? serverName, int level, int filter, out IntPtr buffer, int preferredMaximumLength,
        out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetLocalGroups(string? serverName, string userName, int level, int flags, out IntPtr buffer,
        int preferredMaximumLength, out int entriesRead, out int totalEntries);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    private static List<(string Name, bool Disabled)> EnumerateLocalAccounts(List<string> warnings)
    {
        var accounts = new List<(string Name, bool Disabled)>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var resume = 0;
        try
        {
            // MAX_PREFERRED_LENGTH returns every account in one buffer, so there is no paging loop to get wrong.
            var result = NetUserEnum(null, 1, FilterNormalAccount, out var page, -1, out var read, out _, ref resume);
            if (result != 0)
            {
                warnings.Add($"Local accounts could not be enumerated (netapi32 error {result}); this sweep has none.");
                return accounts;
            }
            if (page == IntPtr.Zero) return accounts;
            try
            {
                var size = Marshal.SizeOf<UserInfo1>();
                for (var i = 0; i < read && accounts.Count < MaximumLocalAccounts; i++)
                {
                    var info = Marshal.PtrToStructure<UserInfo1>(IntPtr.Add(page, i * size));
                    if (string.IsNullOrWhiteSpace(info.Name) || !names.Add(info.Name)) continue;
                    accounts.Add((info.Name, (info.Flags & UfAccountDisable) != 0));
                }
            }
            finally
            {
                NetApiBufferFree(page);
            }
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException or MarshalDirectiveException)
        {
            warnings.Add($"Local account enumeration is unavailable ({ex.GetType().Name}).");
        }
        return accounts;
    }

    /// <summary>
    /// Whether a local account is in the built-in Administrators group. Membership is read per account with
    /// <c>NetUserGetLocalGroups</c>, which resolves only local group names. <c>NetLocalGroupGetMembers</c> at level 3
    /// resolves every member name and can block for minutes on a machine whose domain controller is unreachable — and
    /// this sweep runs inside the service's capture path.
    /// </summary>
    private static bool IsAdministrator(string account, string group)
    {
        var result = NetUserGetLocalGroups(null, account, 0, 0x0001, out var page, -1, out var read, out _);
        if (result != 0 || page == IntPtr.Zero) return false;
        try
        {
            var size = Marshal.SizeOf<LocalGroupUsersInfo0>();
            for (var i = 0; i < read; i++)
            {
                var info = Marshal.PtrToStructure<LocalGroupUsersInfo0>(IntPtr.Add(page, i * size));
                if (string.Equals(info.Name, group, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
        finally
        {
            NetApiBufferFree(page);
        }
    }

    /// <summary>
    /// The localized name of the built-in Administrators group, resolved from its well-known SID with
    /// <c>LookupAccountSid</c>. This is deliberately not <c>NTAccount.Translate</c>: that call can block for a long time
    /// on a machine whose domain controller is unreachable, and this sweep runs inside the service's capture path.
    /// </summary>
    private static string AdministratorsGroupName()
    {
        try
        {
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            var name = new StringBuilder(256);
            var nameLength = name.Capacity;
            var domain = new StringBuilder(256);
            var domainLength = domain.Capacity;
            if (LookupAccountSid(null, bytes, name, ref nameLength, domain, ref domainLength, out _) && name.Length > 0)
                return name.ToString();
        }
        catch (SystemException)
        {
            // Fall through to the English name.
        }
        return "Administrators";
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountSid(string? systemName, byte[] sid, StringBuilder name, ref int nameLength,
        StringBuilder domain, ref int domainLength, out int sidUse);

    internal static bool IsWritableByStandardUsers(string directory) => FileSystemExposure.IsWritableByStandardUsers(directory);

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
