using System.Text.Json;
using System.Text.Json.Serialization;

namespace Downpour.Core;

public enum FixOpKind
{
    SetDword,
    SetString,
    DeleteValue,
    /// <summary>NetbiosOptions = 2 on every adapter under NetBT\Parameters\Interfaces.</summary>
    NetbiosAllInterfaces,
    /// <summary>Disable the local account with this relative ID (500 Administrator, 501 Guest).</summary>
    DisableAccount,
    /// <summary>Firewall on for this profile (1 Domain, 2 Private, 4 Public).</summary>
    FirewallOn,
    /// <summary>MSFT_MpPreference numeric setting.</summary>
    DefenderPreference,
    /// <summary>Add an attack surface reduction rule in block mode.</summary>
    DefenderAsrRule,
    DefenderSignatureUpdate,
}

/// <summary>One fixed operation. Registry paths are under HKEY_LOCAL_MACHINE and come only from this file.</summary>
public sealed record FixOp(FixOpKind Kind, string Path = "", string Name = "", long Number = 0, string Text = "", bool Sensitive = false);

/// <summary>A one-click hardening fix for a posture check with the same Id.</summary>
public sealed record HardeningFix(string Id, string Title, string WhatChanges, IReadOnlyList<FixOp> Ops, bool RebootRequired = false, string? Caution = null);

public sealed record RegistryReading(string Kind, long Number, string Text);

/// <summary>What the elevated fixer can touch. The real implementation lives in Downpour.Fixer; tests use a fake.</summary>
public interface IFixHost
{
    RegistryReading? Read(string path, string name);
    void WriteDword(string path, string name, long value);
    void WriteString(string path, string name, string value);
    void Delete(string path, string name);
    IReadOnlyList<string> SubKeys(string path);
    bool? AccountDisabled(int rid);
    void SetAccountDisabled(int rid, bool disabled);
    bool CurrentUserIs(int rid);
    bool? FirewallEnabled(int profile);
    void SetFirewallEnabled(int profile, bool enabled);
    long? DefenderPreference(string name);
    void SetDefenderPreference(string name, long value);
    int? AsrRuleAction(string ruleId);
    void SetAsrRule(string ruleId, int? action);
    void UpdateDefenderSignatures();
}

/// <summary>The previous state of one changed item, enough to put it back.</summary>
public sealed record FixBackupEntry(string FixId, FixOpKind Kind, string Path, string Name, bool Existed, string? PreviousKind, long PreviousNumber, string? PreviousText, bool Restorable = true);

public sealed record FixBackup(string BackupId, DateTimeOffset CreatedUtc, IReadOnlyList<string> FixIds, IReadOnlyList<FixBackupEntry> Entries);

public sealed record FixOutcome(string FixId, bool Applied, string Message);

public sealed record FixRunResult(string Operation, string? BackupId, IReadOnlyList<FixOutcome> Outcomes, bool RebootRequired, DateTimeOffset FinishedUtc);

/// <summary>
/// One-click fixes for Hardening findings, applied by the elevated Downpour.Fixer after a Windows (UAC) prompt.
/// Each fix records the previous value of everything it changes so the whole batch can be undone; a fix that fails
/// part-way is rolled back immediately. Only the fixes and values in this catalog can ever be applied.
/// </summary>
public static class HardeningFixes
{
    private const string System = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string Lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string LanmanServer = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string DeviceGuard = @"SYSTEM\CurrentControlSet\Control\DeviceGuard";

    private static FixOp Dword(string path, string name, long value) => new(FixOpKind.SetDword, path, name, value);
    private static FixOp Text(string path, string name, string value) => new(FixOpKind.SetString, path, name, Text: value);
    private static FixOp Remove(string path, string name, bool sensitive = false) => new(FixOpKind.DeleteValue, path, name, Sensitive: sensitive);
    private static FixOp Defender(string name, long value) => new(FixOpKind.DefenderPreference, Name: name, Number: value);

    /// <summary>Attack surface reduction rules that rarely affect home use (Microsoft's standard protection set).</summary>
    public static readonly IReadOnlyList<(string Id, string Name)> AsrRules =
    [
        ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from LSASS"),
        ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
        ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
        ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email and webmail"),
        ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block Office apps from creating child processes"),
        ("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office apps from creating executable content"),
        ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office apps from injecting into other processes"),
        ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros"),
        ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned programs that run from USB"),
    ];

    public static readonly IReadOnlyList<HardeningFix> All =
    [
        new("antivirus", "Turn on Defender real-time protection", "Turns on Microsoft Defender real-time protection and updates its definitions.",
            [Defender("DisableRealtimeMonitoring", 0), new(FixOpKind.DefenderSignatureUpdate)],
            Caution: "If another antivirus is registered, Windows keeps Defender in passive mode; turn that antivirus on or uninstall it."),
        new("defender-cloud", "Turn on cloud-delivered protection", "Defender MAPS reporting set to Advanced.", [Defender("MAPSReporting", 2)]),
        new("defender-samples", "Turn on automatic sample submission", "Defender sends safe suspicious samples automatically.", [Defender("SubmitSamplesConsent", 1)]),
        new("defender-pua", "Block potentially unwanted apps", "Defender PUA protection on.", [Defender("PUAProtection", 1)]),
        new("defender-signatures", "Update Defender definitions", "Downloads the newest Defender definitions now.", [new(FixOpKind.DefenderSignatureUpdate)]),
        new("network-protection", "Turn on network protection", "Defender blocks connections to malicious sites from every app.", [Defender("EnableNetworkProtection", 1)]),
        new("controlled-folders", "Turn on ransomware folder protection", "Controlled folder access on.", [Defender("EnableControlledFolderAccess", 1)],
            Caution: "Some games and tools that save into Documents may be blocked until you allow them in Windows Security."),
        new("asr-rules", "Turn on attack surface reduction rules", $"Adds {AsrRules.Count} standard rules in block mode: " + string.Join("; ", AsrRules.Select(r => r.Name)) + ".",
            AsrRules.Select(r => new FixOp(FixOpKind.DefenderAsrRule, Name: r.Id, Number: 1)).ToArray(),
            Caution: "Office macros that start other programs will be blocked."),
        new("firewall", "Turn the firewall on", "Windows Firewall on for Domain, Private and Public networks.",
            [new(FixOpKind.FirewallOn, Number: 1), new(FixOpKind.FirewallOn, Number: 2), new(FixOpKind.FirewallOn, Number: 4)]),
        new("uac", "Restore User Account Control", "UAC on, administrators prompted for consent on the secure desktop.",
            [Dword(System, "EnableLUA", 1), Dword(System, "ConsentPromptBehaviorAdmin", 5), Dword(System, "PromptOnSecureDesktop", 1)], RebootRequired: true),
        new("smartscreen", "Turn on SmartScreen", "SmartScreen warns before unknown downloaded programs run.",
            [Text(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Warn"), Remove(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")]),
        new("driver-blocklist", "Turn on the vulnerable driver blocklist", "Windows blocks known-vulnerable drivers.",
            [Dword(@"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", 1)], RebootRequired: true),
        new("vbs-hvci", "Turn on memory integrity", "Virtualization-based security and hypervisor-enforced code integrity on.",
            [Dword(DeviceGuard, "EnableVirtualizationBasedSecurity", 1), Dword(DeviceGuard + @"\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 1)], RebootRequired: true,
            Caution: "A driver that is not compatible will be blocked after the restart; if a device stops working, use Undo."),
        new("lsa-ppl", "Turn on LSA protection", "LSASS runs as a protected process so tools like Mimikatz cannot read it.", [Dword(Lsa, "RunAsPPL", 2)], RebootRequired: true,
            Caution: "Very old security or smart-card plug-ins that are not signed by Microsoft stop loading."),
        new("credential-guard", "Turn on Credential Guard", "Credential Guard isolates sign-in secrets with virtualization.",
            [Dword(DeviceGuard, "EnableVirtualizationBasedSecurity", 1), Dword(DeviceGuard, "RequirePlatformSecurityFeatures", 1), Dword(Lsa, "LsaCfgFlags", 2)], RebootRequired: true,
            Caution: "Older VPN clients that use MS-CHAPv2 or saved Wi-Fi passwords with PEAP may need to sign in again."),
        new("rdp", "Turn off Remote Desktop", "Remote Desktop connections to this PC are refused.",
            [Dword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1)], Caution: "You will not be able to connect to this PC with Remote Desktop until it is turned on again."),
        new("remote-assistance", "Turn off Remote Assistance", "Remote Assistance invitations are refused.", [Dword(@"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 0)]),
        new("autorun", "Turn off AutoRun for all drives", "AutoRun disabled for every drive type.", [Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255)]),
        new("guest", "Disable the Guest account", "The built-in Guest account is disabled.", [new(FixOpKind.DisableAccount, Number: 501)]),
        new("builtin-admin", "Disable the built-in Administrator", "The built-in Administrator account is disabled.", [new(FixOpKind.DisableAccount, Number: 500)],
            Caution: "Refused if you are signed in as that account."),
        new("autologon", "Remove the stored sign-in password", "Automatic sign-in is turned off and the plain-text password is deleted from the registry.",
            [Text(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "0"), Remove(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", sensitive: true)],
            Caution: "Undo turns automatic sign-in back on but cannot restore the password, which Downpour never stores. Change that password."),
        new("ps-policy", "Set PowerShell to RemoteSigned", "Downloaded scripts must be signed before they run.",
            [Text(@"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy", "RemoteSigned"), Remove(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy")]),
        new("ps-logging", "Turn on PowerShell script logging", "Every PowerShell script block is logged.", [Dword(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1)]),
        new("llmnr", "Turn off LLMNR", "Multicast name resolution off.", [Dword(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0)]),
        new("netbios", "Turn off NetBIOS over TCP/IP", "NetBIOS name service off on every network adapter.", [new(FixOpKind.NetbiosAllInterfaces)],
            Caution: "Very old network drives found only by NetBIOS name may need their IP address."),
        new("wdigest", "Stop clear-text password caching", "WDigest UseLogonCredential set to 0.", [Dword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0)], RebootRequired: true),
        new("lm-hash", "Stop storing LM password hashes", "NoLMHash set to 1 (takes effect at your next password change).", [Dword(Lsa, "NoLMHash", 1)]),
        new("ntlmv1", "Send only NTLMv2", "LAN Manager authentication level 5.", [Dword(Lsa, "LmCompatibilityLevel", 5)], Caution: "Very old NAS boxes that only speak NTLMv1 stop accepting this PC."),
        new("anonymous-sam", "Block anonymous account listing", "RestrictAnonymousSAM set to 1.", [Dword(Lsa, "RestrictAnonymousSAM", 1)]),
        new("smb-signing", "Require SMB signing", "This PC's file shares require signed connections.", [Dword(LanmanServer, "RequireSecuritySignature", 1), Dword(LanmanServer, "EnableSecuritySignature", 1)]),
        new("smb1", "Turn off the SMBv1 server", "SMB1 server protocol off.", [Dword(LanmanServer, "SMB1", 0)], RebootRequired: true),
        new("printnightmare", "Close PrintNightmare", "Point and Print requires elevation and only administrators can install printer drivers.",
            [Dword(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "NoWarningNoElevationOnInstall", 0),
             Dword(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "UpdatePromptSettings", 0),
             Dword(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "RestrictDriverInstallationToAdministrators", 1)]),
        new("remote-registry", "Disable Remote Registry", "Remote Registry service disabled.", [Dword(@"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start", 4)], RebootRequired: true),
        new("winrm", "Stop WinRM starting automatically", "Windows Remote Management set to manual start.", [Dword(@"SYSTEM\CurrentControlSet\Services\WinRM", "Start", 3)], RebootRequired: true),
        new("patch-service", "Re-enable Windows Update", "Windows Update service set to manual (trigger) start.", [Dword(@"SYSTEM\CurrentControlSet\Services\wuauserv", "Start", 3)]),
    ];

    public static HardeningFix? Find(string id) => All.FirstOrDefault(f => f.Id == id);

    public static bool IsValidId(string id) => id.Length is > 0 and <= 32 && id.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-') && Find(id) is not null;

    public static FixRunResult Apply(IFixHost host, IReadOnlyList<string> ids, string backupId, DateTimeOffset now, out FixBackup backup)
    {
        var outcomes = new List<FixOutcome>();
        var entries = new List<FixBackupEntry>();
        var reboot = false;
        foreach (var id in ids.Distinct(StringComparer.Ordinal))
        {
            if (!IsValidId(id)) { outcomes.Add(new(id.Length > 32 ? id[..32] : id, false, "Not an allowed fix; refused.")); continue; }
            var fix = Find(id)!;
            var done = new List<FixBackupEntry>();
            try
            {
                if (fix.Ops.Any(o => o.Kind == FixOpKind.DisableAccount && host.CurrentUserIs((int)o.Number)))
                    throw new InvalidOperationException("You are signed in as this account, so it was not disabled.");
                foreach (var op in Expand(host, fix))
                    done.Add(ApplyOne(host, fix.Id, op));
                entries.AddRange(done);
                reboot |= fix.RebootRequired;
                outcomes.Add(new(id, true, fix.RebootRequired ? $"{fix.Title}: done; takes full effect after a restart." : $"{fix.Title}: done."));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Put back whatever this fix had already changed, newest first.
                var rollbackFailed = 0;
                foreach (var entry in Enumerable.Reverse(done))
                {
                    try { Restore(host, entry); }
                    catch (Exception) { rollbackFailed++; }
                }
                outcomes.Add(new(id, false, $"{fix.Title}: failed ({Short(ex)})" + (rollbackFailed == 0 ? "; nothing was left half-changed." : $"; {rollbackFailed} change(s) could not be put back.")));
            }
        }
        backup = new FixBackup(backupId, now, outcomes.Where(o => o.Applied).Select(o => o.FixId).ToArray(), entries);
        return new FixRunResult("apply", backupId, outcomes, reboot, now);
    }

    public static FixRunResult Undo(IFixHost host, FixBackup backup, DateTimeOffset now)
    {
        var outcomes = new List<FixOutcome>();
        foreach (var group in backup.Entries.Reverse().GroupBy(e => e.FixId))
        {
            var failures = 0;
            var notRestorable = 0;
            foreach (var entry in group)
            {
                if (!entry.Restorable) { notRestorable++; continue; }
                try { Restore(host, entry); }
                catch (Exception) { failures++; }
            }
            var title = Find(group.Key)?.Title ?? group.Key;
            outcomes.Add(new(group.Key, failures == 0,
                failures == 0 ? $"{title}: undone{(notRestorable > 0 ? " (the deleted password cannot be restored)" : "")}." : $"{title}: {failures} change(s) could not be undone."));
        }
        return new FixRunResult("undo", backup.BackupId, outcomes, backup.FixIds.Any(id => Find(id)?.RebootRequired == true), now);
    }

    private static IEnumerable<FixOp> Expand(IFixHost host, HardeningFix fix)
    {
        foreach (var op in fix.Ops)
        {
            if (op.Kind != FixOpKind.NetbiosAllInterfaces) { yield return op; continue; }
            const string interfaces = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
            foreach (var name in host.SubKeys(interfaces).Where(n => n.StartsWith("Tcpip_", StringComparison.OrdinalIgnoreCase) && n.Length <= 64).Take(64))
                yield return Dword($@"{interfaces}\{name}", "NetbiosOptions", 2);
        }
    }

    private static FixBackupEntry ApplyOne(IFixHost host, string fixId, FixOp op)
    {
        switch (op.Kind)
        {
            case FixOpKind.SetDword:
            case FixOpKind.SetString:
            case FixOpKind.DeleteValue:
            {
                var before = host.Read(op.Path, op.Name);
                if (before is not null && before.Kind is not ("dword" or "string"))
                    throw new InvalidOperationException($"{op.Name} has an unexpected value type, so it was left alone.");
                var entry = new FixBackupEntry(fixId, op.Kind, op.Path, op.Name, before is not null, before?.Kind, before?.Number ?? 0,
                    op.Sensitive ? null : before?.Text, Restorable: !op.Sensitive);
                if (op.Kind == FixOpKind.SetDword) host.WriteDword(op.Path, op.Name, op.Number);
                else if (op.Kind == FixOpKind.SetString) host.WriteString(op.Path, op.Name, op.Text);
                else if (before is not null) host.Delete(op.Path, op.Name);
                return entry;
            }
            case FixOpKind.DisableAccount:
            {
                var before = host.AccountDisabled((int)op.Number) ?? throw new InvalidOperationException("The account was not found.");
                host.SetAccountDisabled((int)op.Number, true);
                return new(fixId, op.Kind, "", op.Number.ToString(), true, "bool", before ? 1 : 0, null);
            }
            case FixOpKind.FirewallOn:
            {
                var before = host.FirewallEnabled((int)op.Number) ?? throw new InvalidOperationException("The firewall profile could not be read.");
                host.SetFirewallEnabled((int)op.Number, true);
                return new(fixId, op.Kind, "", op.Number.ToString(), true, "bool", before ? 1 : 0, null);
            }
            case FixOpKind.DefenderPreference:
            {
                var before = host.DefenderPreference(op.Name) ?? throw new InvalidOperationException("Microsoft Defender is not available or not the active antivirus.");
                host.SetDefenderPreference(op.Name, op.Number);
                return new(fixId, op.Kind, "", op.Name, true, "number", before, null);
            }
            case FixOpKind.DefenderAsrRule:
            {
                var before = host.AsrRuleAction(op.Name);
                host.SetAsrRule(op.Name, (int)op.Number);
                return new(fixId, op.Kind, "", op.Name, before is not null, "number", before ?? 0, null);
            }
            case FixOpKind.DefenderSignatureUpdate:
                host.UpdateDefenderSignatures();
                return new(fixId, op.Kind, "", "signatures", false, null, 0, null, Restorable: false);
            default:
                throw new InvalidOperationException("Unsupported operation.");
        }
    }

    private static void Restore(IFixHost host, FixBackupEntry e)
    {
        switch (e.Kind)
        {
            case FixOpKind.SetDword:
            case FixOpKind.SetString:
            case FixOpKind.DeleteValue:
                if (!e.Existed) host.Delete(e.Path, e.Name);
                else if (e.PreviousKind == "dword") host.WriteDword(e.Path, e.Name, e.PreviousNumber);
                else if (e.PreviousText is not null) host.WriteString(e.Path, e.Name, e.PreviousText);
                break;
            case FixOpKind.DisableAccount:
                host.SetAccountDisabled(int.Parse(e.Name), e.PreviousNumber == 1);
                break;
            case FixOpKind.FirewallOn:
                host.SetFirewallEnabled(int.Parse(e.Name), e.PreviousNumber == 1);
                break;
            case FixOpKind.DefenderPreference:
                host.SetDefenderPreference(e.Name, e.PreviousNumber);
                break;
            case FixOpKind.DefenderAsrRule:
                host.SetAsrRule(e.Name, e.Existed ? (int)e.PreviousNumber : null);
                break;
        }
    }

    private static string Short(Exception ex) => (ex.Message.Length > 160 ? ex.Message[..160] : ex.Message).ReplaceLineEndings(" ");

    public static readonly JsonSerializerOptions Json = new() { WriteIndented = false, Converters = { new JsonStringEnumConverter() } };
}
