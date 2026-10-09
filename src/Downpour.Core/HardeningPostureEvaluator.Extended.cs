using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Readings for the v29 system_hardening.py checks and the NSA/CIS-style credential, network and patch checks.</summary>
public sealed partial record PostureReadings
{
    /// <summary>Defender (MSFT_MpComputerStatus / MSFT_MpPreference); null when Defender's WMI provider is unreadable.</summary>
    public DefenderReading? Defender { get; init; }
    /// <summary>EnableFirewall per profile (Domain, Private, Public), policy value taking precedence.</summary>
    public IReadOnlyDictionary<string, int?>? FirewallProfiles { get; init; }
    public int? EnableLua { get; init; }
    public int? ConsentPromptBehaviorAdmin { get; init; }
    public int? PromptOnSecureDesktop { get; init; }
    public int? DenyTsConnections { get; init; }
    public int? RdpUserAuthentication { get; init; }
    public int? RemoteAssistanceAllowed { get; init; }
    public int? NoDriveTypeAutoRun { get; init; }
    public string? PowerShellExecutionPolicy { get; init; }
    public bool PowerShell2Installed { get; init; }
    public int? ScriptBlockLogging { get; init; }
    /// <summary>Built-in Guest (-501) and Administrator (-500) accounts: true when enabled; null when unreadable.</summary>
    public bool? GuestEnabled { get; init; }
    public bool? BuiltInAdministratorEnabled { get; init; }
    public int? LlmnrEnabled { get; init; }
    /// <summary>Interfaces whose NetbiosOptions is not 2 (disabled).</summary>
    public int? NetbiosEnabledInterfaces { get; init; }
    public int? WDigestUseLogonCredential { get; init; }
    public int? NoLmHash { get; init; }
    public int? LmCompatibilityLevel { get; init; }
    public int? RestrictAnonymousSam { get; init; }
    public int? SmbServerRequireSigning { get; init; }
    public int? Smb1ClientStart { get; init; }
    public int? PointAndPrintNoWarningNoElevation { get; init; }
    public int? SpoolerStart { get; init; }
    public int? RemoteRegistryStart { get; init; }
    public int? WinRmStart { get; init; }
    public string? SmartScreen { get; init; }
    public int? SmartScreenPolicy { get; init; }
    public int? VulnerableDriverBlocklist { get; init; }
    public bool AutoLogonWithStoredPassword { get; init; }
    /// <summary>Newest installed update date (Win32_QuickFixEngineering) and the OS build.</summary>
    public DateTimeOffset? LastUpdateInstalled { get; init; }
    public int? OsBuild { get; init; }
    public int? OsRevision { get; init; }
    public string? OsDisplayVersion { get; init; }
    public string? OsEdition { get; init; }
    /// <summary>Windows Insider channel (WindowsSelfHost\Applicability BranchName); empty when an Insider build is no longer enrolled.</summary>
    public string? InsiderBranch { get; init; }
}

public sealed record DefenderReading(
    bool? Primary,
    bool? RealTime,
    bool? TamperProtected,
    int? SignatureAgeDays,
    int? MapsReporting,
    int? SubmitSamplesConsent,
    int? PuaProtection,
    int? ControlledFolderAccess,
    int? NetworkProtection,
    int? AsrRulesEnabled);

public static partial class HardeningPostureEvaluator
{
    /// <summary>The extended checks, grouped as Windows Security shows them.</summary>
    public static IReadOnlyList<PostureCheck> EvaluateExtended(PostureReadings r, DateTimeOffset now) =>
    [
        DefenderCloud(r), DefenderSamples(r), DefenderPua(r), DefenderTamper(r), DefenderSignatures(r), ControlledFolders(r), NetworkProtection(r), AsrRules(r),
        Firewall(r), Uac(r), SmartScreen(r), DriverBlocklist(r),
        RemoteDesktop(r), RemoteAssistance(r), AutoRun(r), Guest(r), BuiltInAdministrator(r), AutoLogon(r),
        PowerShellPolicy(r), PowerShell2(r), ScriptBlockLogging(r),
        Llmnr(r), Netbios(r), WDigest(r), LmHash(r), NtlmV1(r), AnonymousSam(r), SmbSigning(r), Smb1Client(r),
        PrintNightmare(r), RemoteRegistry(r), WinRm(r),
        UpdateAge(r, now), OsSupport(r, now),
    ];

    private const string DefenderNote = "Defender is not the active antivirus, so its own settings do not apply.";

    private static PostureCheck? NotPrimary(PostureReadings r, string id, string title, string technique) =>
        r.Defender is null ? Unknown(id, title, technique, "Microsoft Defender settings could not be read (another antivirus may be active, or administrator rights are needed).")
        : r.Defender.Primary == false ? Pass(id, title, technique, DefenderNote) : null;

    internal static PostureCheck DefenderCloud(PostureReadings r) => NotPrimary(r, "defender-cloud", "Defender cloud-delivered protection", "T1562.001") ?? (r.Defender!.MapsReporting switch
    {
        null => Unknown("defender-cloud", "Defender cloud-delivered protection", "T1562.001", "MAPS setting could not be read."),
        0 => Finding("defender-cloud", "Defender cloud-delivered protection", "MEDIUM", "T1562.001", "Cloud-delivered protection is off, so brand-new malware is caught later."),
        _ => Pass("defender-cloud", "Defender cloud-delivered protection", "T1562.001", "Cloud-delivered protection is on."),
    });

    internal static PostureCheck DefenderSamples(PostureReadings r) => NotPrimary(r, "defender-samples", "Defender automatic sample submission", "T1562.001") ?? (r.Defender!.SubmitSamplesConsent switch
    {
        null => Unknown("defender-samples", "Defender automatic sample submission", "T1562.001", "Sample submission setting could not be read."),
        2 => Finding("defender-samples", "Defender automatic sample submission", "LOW", "T1562.001", "Sample submission is off; Defender cannot send suspicious files for deeper cloud analysis (privacy choice, lowers detection)."),
        _ => Pass("defender-samples", "Defender automatic sample submission", "T1562.001", "Suspicious files can be sent for cloud analysis."),
    });

    internal static PostureCheck DefenderPua(PostureReadings r) => NotPrimary(r, "defender-pua", "Potentially unwanted app blocking", "T1204") ?? (r.Defender!.PuaProtection switch
    {
        null => Unknown("defender-pua", "Potentially unwanted app blocking", "T1204", "PUA setting could not be read."),
        0 => Finding("defender-pua", "Potentially unwanted app blocking", "MEDIUM", "T1204", "Adware, bundleware and fake optimisers are not blocked."),
        _ => Pass("defender-pua", "Potentially unwanted app blocking", "T1204", r.Defender.PuaProtection == 2 ? "PUA protection is in audit mode." : "PUA protection is on."),
    });

    internal static PostureCheck DefenderTamper(PostureReadings r) => NotPrimary(r, "defender-tamper", "Defender tamper protection", "T1562.001") ?? (r.Defender!.TamperProtected switch
    {
        null => Unknown("defender-tamper", "Defender tamper protection", "T1562.001", "Tamper protection state could not be read."),
        false => Finding("defender-tamper", "Defender tamper protection", "HIGH", "T1562.001", "Tamper protection is off: malware with admin rights can switch Defender off."),
        true => Pass("defender-tamper", "Defender tamper protection", "T1562.001", "Tamper protection is on."),
    });

    internal static PostureCheck DefenderSignatures(PostureReadings r) => NotPrimary(r, "defender-signatures", "Defender definitions age", "T1562.001") ?? (r.Defender!.SignatureAgeDays switch
    {
        null => Unknown("defender-signatures", "Defender definitions age", "T1562.001", "Definition age could not be read."),
        > 7 => Finding("defender-signatures", "Defender definitions age", "HIGH", "T1562.001", $"Definitions are {r.Defender.SignatureAgeDays} days old."),
        > 2 => Finding("defender-signatures", "Defender definitions age", "MEDIUM", "T1562.001", $"Definitions are {r.Defender.SignatureAgeDays} days old."),
        _ => Pass("defender-signatures", "Defender definitions age", "T1562.001", $"Definitions are {r.Defender.SignatureAgeDays} day(s) old."),
    });

    internal static PostureCheck ControlledFolders(PostureReadings r) => NotPrimary(r, "controlled-folders", "Ransomware protection (controlled folder access)", "T1486") ?? (r.Defender!.ControlledFolderAccess switch
    {
        null => Unknown("controlled-folders", "Ransomware protection (controlled folder access)", "T1486", "Controlled folder access could not be read."),
        1 => Pass("controlled-folders", "Ransomware protection (controlled folder access)", "T1486", "Untrusted programs cannot change Documents, Pictures and other protected folders."),
        _ => Finding("controlled-folders", "Ransomware protection (controlled folder access)", "LOW", "T1486", "Controlled folder access is off; any program can encrypt your documents. Optional: it can block some games and tools until allowed."),
    });

    internal static PostureCheck NetworkProtection(PostureReadings r) => NotPrimary(r, "network-protection", "Defender network protection", "T1071") ?? (r.Defender!.NetworkProtection switch
    {
        null => Unknown("network-protection", "Defender network protection", "T1071", "Network protection could not be read."),
        1 => Pass("network-protection", "Defender network protection", "T1071", "Connections to known malicious sites are blocked for all apps."),
        _ => Finding("network-protection", "Defender network protection", "LOW", "T1071", "Network protection is off; only browsers with SmartScreen block malicious sites."),
    });

    internal static PostureCheck AsrRules(PostureReadings r) => NotPrimary(r, "asr-rules", "Attack surface reduction rules", "T1204.002") ?? (r.Defender!.AsrRulesEnabled switch
    {
        null => Unknown("asr-rules", "Attack surface reduction rules", "T1204.002", "ASR rules could not be read."),
        0 => Finding("asr-rules", "Attack surface reduction rules", "LOW", "T1204.002", "No ASR rules are on (they block Office macros starting programs, credential theft from LSASS, and more). Set through Group Policy or Intune."),
        _ => Pass("asr-rules", "Attack surface reduction rules", "T1204.002", $"{r.Defender.AsrRulesEnabled} ASR rule(s) block or audit."),
    });

    internal static PostureCheck Firewall(PostureReadings r)
    {
        const string title = "Windows Firewall (all profiles)";
        if (r.FirewallProfiles is not { Count: > 0 } profiles) return Unknown("firewall", title, "T1562.004", "Firewall profile state could not be read.");
        var off = profiles.Where(p => p.Value == 0).Select(p => p.Key).ToArray();
        return off.Length == 0
            ? Pass("firewall", title, "T1562.004", $"On for {string.Join(", ", profiles.Keys)} networks.")
            : Finding("firewall", title, off.Contains("Public") ? "HIGH" : "MEDIUM", "T1562.004", $"Firewall is off for {string.Join(", ", off)} networks.");
    }

    internal static PostureCheck Uac(PostureReadings r)
    {
        const string title = "User Account Control";
        if (r.EnableLua == 0) return Finding("uac", title, "HIGH", "T1548.002", "UAC is off: every program runs with full administrator rights.");
        if (r.ConsentPromptBehaviorAdmin == 0) return Finding("uac", title, "HIGH", "T1548.002", "Administrators are elevated without any prompt, so malware gets admin rights silently.");
        if (r.PromptOnSecureDesktop == 0) return Finding("uac", title, "LOW", "T1548.002", "UAC prompts are not on the secure desktop, so other programs can interact with them.");
        return r.EnableLua is null ? Unknown("uac", title, "T1548.002", "UAC settings could not be read.") : Pass("uac", title, "T1548.002", "UAC is on and prompts on the secure desktop.");
    }

    internal static PostureCheck SmartScreen(PostureReadings r)
    {
        const string title = "SmartScreen for apps and files";
        if (r.SmartScreenPolicy == 0 || string.Equals(r.SmartScreen, "Off", StringComparison.OrdinalIgnoreCase))
            return Finding("smartscreen", title, "MEDIUM", "T1204.002", "SmartScreen is off: downloaded programs with no reputation run without a warning.");
        return Pass("smartscreen", title, "T1204.002", "SmartScreen warns before unknown downloaded programs run.");
    }

    internal static PostureCheck DriverBlocklist(PostureReadings r) => r.VulnerableDriverBlocklist switch
    {
        0 => Finding("driver-blocklist", "Microsoft vulnerable driver blocklist", "MEDIUM", "T1068", "The blocklist is off, so known-vulnerable drivers attackers use to kill security software can load."),
        _ => Pass("driver-blocklist", "Microsoft vulnerable driver blocklist", "T1068", "Known-vulnerable drivers are blocked from loading."),
    };

    internal static PostureCheck RemoteDesktop(PostureReadings r) => (r.DenyTsConnections, r.RdpUserAuthentication) switch
    {
        (null, _) => Unknown("rdp", "Remote Desktop", "T1021.001", "Remote Desktop state could not be read."),
        (0, 0) => Finding("rdp", "Remote Desktop", "HIGH", "T1021.001", "Remote Desktop is on without Network Level Authentication, so anyone who can reach this PC gets a login screen (BlueKeep-class attacks)."),
        (0, _) => Finding("rdp", "Remote Desktop", "MEDIUM", "T1021.001", "Remote Desktop is on. Turn it off if you do not use it; it is a common entry point for ransomware gangs."),
        _ => Pass("rdp", "Remote Desktop", "T1021.001", "Remote Desktop is off."),
    };

    internal static PostureCheck RemoteAssistance(PostureReadings r) => r.RemoteAssistanceAllowed switch
    {
        1 => Finding("remote-assistance", "Remote Assistance", "LOW", "T1219", "Remote Assistance invitations are allowed. Tech-support scammers use it; turn it off if you do not need it."),
        _ => Pass("remote-assistance", "Remote Assistance", "T1219", "Remote Assistance is off."),
    };

    internal static PostureCheck AutoRun(PostureReadings r) => r.NoDriveTypeAutoRun switch
    {
        >= 0xFF => Pass("autorun", "AutoRun for all drives", "T1091", "AutoRun is off for every drive type."),
        _ => Finding("autorun", "AutoRun for all drives", "LOW", "T1091", "AutoRun is not turned off for every drive type; a USB stick or disc can offer to run its program."),
    };

    internal static PostureCheck Guest(PostureReadings r) => r.GuestEnabled switch
    {
        null => Unknown("guest", "Guest account", "T1078.001", "Guest account state could not be read."),
        true => Finding("guest", "Guest account", "MEDIUM", "T1078.001", "The built-in Guest account is enabled."),
        false => Pass("guest", "Guest account", "T1078.001", "Guest account is disabled."),
    };

    internal static PostureCheck BuiltInAdministrator(PostureReadings r) => r.BuiltInAdministratorEnabled switch
    {
        null => Unknown("builtin-admin", "Built-in Administrator account", "T1078.003", "Account state could not be read."),
        true => Finding("builtin-admin", "Built-in Administrator account", "MEDIUM", "T1078.003", "The built-in Administrator account is enabled; it never shows UAC prompts and is a password-guessing target."),
        false => Pass("builtin-admin", "Built-in Administrator account", "T1078.003", "Built-in Administrator is disabled."),
    };

    internal static PostureCheck AutoLogon(PostureReadings r) => r.AutoLogonWithStoredPassword
        ? Finding("autologon", "Automatic sign-in with a stored password", "HIGH", "T1552.002", "Windows signs in automatically using a password saved in plain text in the registry, readable by any administrator program.")
        : Pass("autologon", "Automatic sign-in with a stored password", "T1552.002", "No plain-text auto sign-in password is stored.");

    internal static PostureCheck PowerShellPolicy(PostureReadings r) => r.PowerShellExecutionPolicy?.ToLowerInvariant() switch
    {
        "unrestricted" or "bypass" => Finding("ps-policy", "PowerShell execution policy", "LOW", "T1059.001", $"Machine policy is {r.PowerShellExecutionPolicy}; downloaded scripts run without a prompt. (Execution policy is a safety catch, not a security boundary.)"),
        null => Pass("ps-policy", "PowerShell execution policy", "T1059.001", "Default policy (scripts need to be signed or local)."),
        _ => Pass("ps-policy", "PowerShell execution policy", "T1059.001", $"Machine policy is {r.PowerShellExecutionPolicy}."),
    };

    internal static PostureCheck PowerShell2(PostureReadings r) => r.PowerShell2Installed
        ? Finding("ps-v2", "PowerShell 2.0 engine", "MEDIUM", "T1059.001", "The old PowerShell 2.0 engine is installed; attackers start it to skip AMSI scanning and script logging.")
        : Pass("ps-v2", "PowerShell 2.0 engine", "T1059.001", "PowerShell 2.0 is not installed.");

    internal static PostureCheck ScriptBlockLogging(PostureReadings r) => r.ScriptBlockLogging switch
    {
        1 => Pass("ps-logging", "PowerShell script block logging", "T1059.001", "Every PowerShell script is logged for investigation."),
        _ => Finding("ps-logging", "PowerShell script block logging", "LOW", "T1059.001", "Only suspicious scripts are logged; turning on full logging gives Downpour and investigators complete script evidence."),
    };

    internal static PostureCheck Llmnr(PostureReadings r) => r.LlmnrEnabled switch
    {
        0 => Pass("llmnr", "LLMNR name resolution", "T1557.001", "LLMNR is off."),
        _ => Finding("llmnr", "LLMNR name resolution", "LOW", "T1557.001", "LLMNR is on: on shared Wi-Fi, a tool like Responder can answer name lookups and capture your password hash."),
    };

    internal static PostureCheck Netbios(PostureReadings r) => r.NetbiosEnabledInterfaces switch
    {
        null => Unknown("netbios", "NetBIOS over TCP/IP", "T1557.001", "NetBIOS settings could not be read."),
        0 => Pass("netbios", "NetBIOS over TCP/IP", "T1557.001", "NetBIOS is off on every adapter."),
        _ => Finding("netbios", "NetBIOS over TCP/IP", "LOW", "T1557.001", $"NetBIOS name service is on for {r.NetbiosEnabledInterfaces} adapter(s); like LLMNR it can leak password hashes on untrusted networks."),
    };

    internal static PostureCheck WDigest(PostureReadings r) => r.WDigestUseLogonCredential switch
    {
        1 => Finding("wdigest", "WDigest clear-text passwords", "HIGH", "T1003.001", "UseLogonCredential=1: your password is kept in memory in clear text where Mimikatz can read it. Malware sets this deliberately."),
        _ => Pass("wdigest", "WDigest clear-text passwords", "T1003.001", "Passwords are not cached in clear text."),
    };

    internal static PostureCheck LmHash(PostureReadings r) => r.NoLmHash switch
    {
        0 => Finding("lm-hash", "LAN Manager password hashes", "MEDIUM", "T1003.002", "NoLMHash=0: weak LM hashes of passwords are stored and crack in seconds."),
        _ => Pass("lm-hash", "LAN Manager password hashes", "T1003.002", "LM hashes are not stored."),
    };

    internal static PostureCheck NtlmV1(PostureReadings r) => r.LmCompatibilityLevel switch
    {
        < 3 => Finding("ntlmv1", "NTLMv1 authentication", "MEDIUM", "T1557", $"LmCompatibilityLevel={r.LmCompatibilityLevel}: this PC still sends LM/NTLMv1 responses, which can be cracked or relayed."),
        _ => Pass("ntlmv1", "NTLMv1 authentication", "T1557", "Only NTLMv2 is sent."),
    };

    internal static PostureCheck AnonymousSam(PostureReadings r) => r.RestrictAnonymousSam switch
    {
        0 => Finding("anonymous-sam", "Anonymous account listing", "LOW", "T1087.001", "Anonymous users can list this PC's accounts."),
        _ => Pass("anonymous-sam", "Anonymous account listing", "T1087.001", "Anonymous account enumeration is blocked."),
    };

    internal static PostureCheck SmbSigning(PostureReadings r) => r.SmbServerRequireSigning switch
    {
        1 => Pass("smb-signing", "SMB signing (file sharing)", "T1557", "SMB signing is required, blocking relay attacks on file sharing."),
        _ => Finding("smb-signing", "SMB signing (file sharing)", "LOW", "T1557", "SMB signing is not required for this PC's shares, so NTLM relay attacks against it are possible."),
    };

    internal static PostureCheck Smb1Client(PostureReadings r) => r.Smb1ClientStart switch
    {
        null or 4 => Pass("smb1-client", "SMBv1 client", "T1210", "The SMBv1 client is not installed or is disabled."),
        _ => Finding("smb1-client", "SMBv1 client", "MEDIUM", "T1210", "The SMBv1 client driver is enabled; remove the SMB 1.0 feature unless an old NAS needs it."),
    };

    internal static PostureCheck PrintNightmare(PostureReadings r) => (r.PointAndPrintNoWarningNoElevation, r.SpoolerStart) switch
    {
        (1, not 4) => Finding("printnightmare", "PrintNightmare (CVE-2021-34527)", "HIGH", "T1068", "Point and Print is set to install printer drivers without a warning or elevation, re-opening PrintNightmare even on patched PCs."),
        _ => Pass("printnightmare", "PrintNightmare (CVE-2021-34527)", "T1068", r.SpoolerStart == 4 ? "Print Spooler is disabled." : "Point and Print requires elevation (the patched default)."),
    };

    internal static PostureCheck RemoteRegistry(PostureReadings r) => r.RemoteRegistryStart switch
    {
        2 => Finding("remote-registry", "Remote Registry service", "LOW", "T1012", "Remote Registry starts automatically, letting other computers read this PC's registry."),
        _ => Pass("remote-registry", "Remote Registry service", "T1012", "Remote Registry does not start automatically."),
    };

    internal static PostureCheck WinRm(PostureReadings r) => r.WinRmStart switch
    {
        2 => Finding("winrm", "Windows Remote Management", "LOW", "T1021.006", "WinRM starts automatically; remote PowerShell may be reachable. Normal on managed work PCs."),
        _ => Pass("winrm", "Windows Remote Management", "T1021.006", "WinRM does not start automatically."),
    };

    internal static PostureCheck UpdateAge(PostureReadings r, DateTimeOffset now)
    {
        const string title = "Security updates installed";
        if (r.LastUpdateInstalled is not { } last) return Unknown("update-age", title, "T1190", "The installed update history could not be read.");
        var days = (int)(now - last).TotalDays;
        return days switch
        {
            > 60 => Finding("update-age", title, "HIGH", "T1190", $"The newest update was installed {days} days ago ({last:yyyy-MM-dd}); this PC is missing at least two months of security fixes, including actively exploited ones."),
            > 35 => Finding("update-age", title, "MEDIUM", "T1190", $"The newest update was installed {days} days ago ({last:yyyy-MM-dd}); this month's Patch Tuesday fixes are probably missing."),
            _ => Pass("update-age", title, "T1190", $"Updated {Math.Max(days, 0)} day(s) ago ({last:yyyy-MM-dd})."),
        };
    }

    /// <summary>Windows 10/11 feature releases and their end of security updates for Home and Pro (Microsoft lifecycle).</summary>
    private static readonly (int Build, string Name, DateTimeOffset End)[] Releases =
    [
        (19045, "Windows 10 22H2", new(2025, 10, 14, 0, 0, 0, TimeSpan.Zero)),
        (22000, "Windows 11 21H2", new(2023, 10, 10, 0, 0, 0, TimeSpan.Zero)),
        (22621, "Windows 11 22H2", new(2024, 10, 8, 0, 0, 0, TimeSpan.Zero)),
        (22631, "Windows 11 23H2", new(2025, 11, 11, 0, 0, 0, TimeSpan.Zero)),
        (26100, "Windows 11 24H2", new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero)),
        (26200, "Windows 11 25H2", new(2027, 10, 12, 0, 0, 0, TimeSpan.Zero)),
    ];

    internal static PostureCheck OsSupport(PostureReadings r, DateTimeOffset now)
    {
        const string title = "Windows version support";
        if (r.OsBuild is not { } build) return Unknown("os-support", title, "T1190", "The Windows build could not be read.");
        var label = $"{r.OsEdition} {r.OsDisplayVersion} (build {build}.{r.OsRevision})".Trim();
        if (build > Releases[^1].Build)
            return string.IsNullOrWhiteSpace(r.InsiderBranch)
                ? Finding("os-support", title, "HIGH", "T1190", $"{label} is a Windows Insider preview build, but this PC is no longer enrolled in the Insider Program, so Windows Update offers it nothing. Re-join the Insider Program (Settings > Windows Update > Windows Insider Program) or reinstall a released Windows 11; preview builds also expire.")
                : Pass("os-support", title, "T1190", $"{label} is an Insider build on the {r.InsiderBranch} channel; it updates through the Insider Program.");
        var release = Releases.FirstOrDefault(x => x.Build == build);
        if (release.Name is null)
            return build < 19045
                ? Finding("os-support", title, "CRITICAL", "T1190", $"{label} no longer receives security updates. Every newly found Windows vulnerability stays open.")
                : Unknown("os-support", title, "T1190", $"{label} is not in Downpour's release table.");
        var left = (int)(release.End - now).TotalDays;
        if (left < 0)
            return Finding("os-support", title, "CRITICAL", "T1190", $"{release.Name} stopped receiving security updates on {release.End:yyyy-MM-dd} (Home and Pro; Enterprise and Education or Extended Security Updates may differ). Upgrade to keep getting fixes.");
        if (left < 60)
            return Finding("os-support", title, "MEDIUM", "T1190", $"{release.Name} stops receiving security updates on {release.End:yyyy-MM-dd} ({left} days). Install the newest feature update.");
        return Pass("os-support", title, "T1190", $"{label} is supported until {release.End:yyyy-MM-dd}.");
    }
}
