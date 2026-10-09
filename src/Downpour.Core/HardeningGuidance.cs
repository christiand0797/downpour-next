using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// How to fix each posture finding by hand, and the Windows Security or Settings page that does it. Downpour does not
/// change these settings itself (read-only until an audited elevated broker exists); the person applies the fix in
/// Windows' own UI, which asks for administrator rights where needed. Only fixed ms-settings: and windowsdefender: links.
/// </summary>
public static class HardeningGuidance
{
    public const string Protection = "Virus & threat protection";
    public const string Device = "Device security";
    public const string Network = "Network & sharing";
    public const string Accounts = "Accounts & sign-in";
    public const string Credentials = "Credential protection";
    public const string Scripting = "Scripting & logging";
    public const string Updates = "Updates & CVE exposure";

    private sealed record Entry(string Category, string Fix, string? Uri = null);

    private const string GroupPolicy = "Group Policy (gpedit.msc, Pro and above)";

    private static readonly Dictionary<string, Entry> Entries = new(StringComparer.Ordinal)
    {
        ["antivirus"] = new(Protection, "Open Windows Security > Virus & threat protection and turn on real-time protection, or turn it on in your antivirus.", "windowsdefender://threat"),
        ["defender-cloud"] = new(Protection, "Windows Security > Virus & threat protection > Manage settings > turn on Cloud-delivered protection.", "windowsdefender://threatsettings"),
        ["defender-samples"] = new(Protection, "Windows Security > Virus & threat protection > Manage settings > turn on Automatic sample submission.", "windowsdefender://threatsettings"),
        ["defender-pua"] = new(Protection, "Windows Security > App & browser control > Reputation-based protection > turn on Potentially unwanted app blocking (Block apps and Block downloads).", "windowsdefender://appbrowser"),
        ["defender-tamper"] = new(Protection, "Windows Security > Virus & threat protection > Manage settings > turn on Tamper Protection. If it is greyed out, an organisation policy or another program controls it.", "windowsdefender://threatsettings"),
        ["defender-signatures"] = new(Protection, "Windows Security > Virus & threat protection > Protection updates > Check for updates.", "windowsdefender://threat"),
        ["controlled-folders"] = new(Protection, "Windows Security > Virus & threat protection > Ransomware protection > turn on Controlled folder access, then allow any trusted app it blocks.", "windowsdefender://ransomwareprotection"),
        ["network-protection"] = new(Protection, $"Set through {GroupPolicy}: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Network Protection > Block."),
        ["asr-rules"] = new(Protection, $"Set through {GroupPolicy}: ... > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules. Start with 'Block credential stealing from LSASS' (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2) and 'Block Office apps from creating child processes' (d4f940ab-401b-4efc-aadc-ad5f3c50688a)."),
        ["firewall"] = new(Network, "Windows Security > Firewall & network protection > turn the firewall on for Domain, Private and Public networks.", "windowsdefender://network"),
        ["uac"] = new(Accounts, "Start > type 'UAC' > Change User Account Control settings > set the slider to the default (second from top) or higher, then restart."),
        ["smartscreen"] = new(Protection, "Windows Security > App & browser control > Reputation-based protection > turn on Check apps and files.", "windowsdefender://appbrowser"),
        ["driver-blocklist"] = new(Device, "Windows Security > Device security > Core isolation details > turn on Microsoft Vulnerable Driver Blocklist.", "windowsdefender://devicesecurity"),
        ["vbs-hvci"] = new(Device, "Windows Security > Device security > Core isolation details > turn on Memory integrity, then restart. Incompatible drivers are listed there; update or remove them first.", "windowsdefender://devicesecurity"),
        ["credential-guard"] = new(Credentials, $"Optional. Set through {GroupPolicy}: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security > Credential Guard: Enabled with UEFI lock."),
        ["lsa-ppl"] = new(Credentials, "Windows Security > Device security > Core isolation details > turn on Local Security Authority protection, then restart.", "windowsdefender://devicesecurity"),
        ["secure-boot"] = new(Device, "Restart into your PC's UEFI/BIOS setup (Settings > System > Recovery > Advanced startup > UEFI Firmware Settings) and enable Secure Boot.", "ms-settings:recovery"),
        ["tpm"] = new(Device, "Enable the TPM (Intel PTT or AMD fTPM) in your PC's UEFI/BIOS setup.", "ms-settings:recovery"),
        ["bitlocker"] = new(Device, "Settings > Privacy & security > Device encryption (Home) or Control Panel > BitLocker Drive Encryption (Pro), and save the recovery key somewhere safe.", "ms-settings:deviceencryption"),
        ["rdp"] = new(Network, "Settings > System > Remote Desktop > turn it off. If you need it, keep 'Require devices to use Network Level Authentication' on and never expose port 3389 to the internet.", "ms-settings:remotedesktop"),
        ["remote-assistance"] = new(Network, "Start > type 'Allow Remote Assistance' > System Properties > Remote > clear 'Allow Remote Assistance connections to this computer'. No genuine company will ask you to turn it on."),
        ["autorun"] = new(Device, "Settings > Bluetooth & devices > AutoPlay > turn off 'Use AutoPlay for all media and devices'.", "ms-settings:autoplay"),
        ["guest"] = new(Accounts, "Computer Management > Local Users and Groups > Users > Guest > Properties > Account is disabled.", "ms-settings:otherusers"),
        ["builtin-admin"] = new(Accounts, "Computer Management > Local Users and Groups > Users > Administrator > Properties > Account is disabled. Use your own account with UAC instead.", "ms-settings:otherusers"),
        ["autologon"] = new(Accounts, "Run netplwiz, tick 'Users must enter a user name and password', and change the password that was stored, since it was readable in the registry.", "ms-settings:signinoptions"),
        ["ps-policy"] = new(Scripting, "In an administrator terminal run: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"),
        ["ps-v2"] = new(Scripting, "Start > 'Turn Windows features on or off' > clear Windows PowerShell 2.0 (or in an administrator terminal: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).", "ms-settings:optionalfeatures"),
        ["ps-logging"] = new(Scripting, $"{GroupPolicy}: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging: Enabled."),
        ["llmnr"] = new(Network, $"{GroupPolicy}: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution: Enabled."),
        ["netbios"] = new(Network, "Control Panel > Network Connections > adapter > Properties > Internet Protocol Version 4 > Advanced > WINS > Disable NetBIOS over TCP/IP (for each adapter).", "ms-settings:network-advancedsettings"),
        ["wdigest"] = new(Credentials, "Something switched on clear-text password caching (a known malware step). Delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential or set it to 0, restart, change your password, and run a full scan."),
        ["lm-hash"] = new(Credentials, $"{GroupPolicy}: Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change: Enabled. Then change your password."),
        ["ntlmv1"] = new(Credentials, $"{GroupPolicy}: Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level: Send NTLMv2 response only. Refuse LM & NTLM."),
        ["anonymous-sam"] = new(Credentials, $"{GroupPolicy}: Security Options > Network access: Do not allow anonymous enumeration of SAM accounts: Enabled."),
        ["smb-signing"] = new(Network, $"{GroupPolicy}: Security Options > Microsoft network server: Digitally sign communications (always): Enabled. Windows 11 24H2 requires this by default."),
        ["smb1"] = new(Network, "Start > 'Turn Windows features on or off' > clear SMB 1.0/CIFS File Sharing Support, then restart.", "ms-settings:optionalfeatures"),
        ["smb1-client"] = new(Network, "Start > 'Turn Windows features on or off' > clear SMB 1.0/CIFS File Sharing Support, then restart.", "ms-settings:optionalfeatures"),
        ["printnightmare"] = new(Updates, $"Install all updates, then in {GroupPolicy}: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions: Enabled, with both security prompts set to 'Show warning and elevation prompt'. If you never print, disable the Print Spooler service.", "ms-settings:windowsupdate"),
        ["remote-registry"] = new(Network, "Start > services.msc > Remote Registry > Startup type: Disabled (unless your IT department uses it)."),
        ["winrm"] = new(Network, "If this is a home PC: services.msc > Windows Remote Management > Startup type: Manual, and run 'winrm delete winrm/config/Listener?Address=*+Transport=HTTP' in an administrator terminal."),
        ["patch-service"] = new(Updates, "Start > services.msc > Windows Update > Startup type: Manual (Trigger Start), then Settings > Windows Update > Check for updates.", "ms-settings:windowsupdate"),
        ["update-age"] = new(Updates, "Settings > Windows Update > Check for updates, install everything including optional quality updates, and restart.", "ms-settings:windowsupdate"),
        ["os-support"] = new(Updates, "Settings > Windows Update > install the newest Windows 11 feature update (or enrol in Extended Security Updates for Windows 10).", "ms-settings:windowsupdate"),
    };

    /// <summary>Fixed deep links the desktop is allowed to open for a check.</summary>
    public static readonly IReadOnlySet<string> AllowedUris = Entries.Values.Select(e => e.Uri).OfType<string>().ToHashSet(StringComparer.Ordinal);

    public static PostureCheck Apply(PostureCheck check) => Entries.TryGetValue(check.Id, out var entry)
        ? check with { Category = entry.Category, Fix = check.State == PostureStates.Pass ? null : entry.Fix, SettingsUri = check.State == PostureStates.Pass ? null : entry.Uri }
        : check;
}
