using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Raw, unevaluated platform readings. Null means the value could not be read.</summary>
public sealed record PostureReadings
{
    /// <summary>Win32_EncryptableVolume.ProtectionStatus for the OS volume: 0 off, 1 on, 2 unknown.</summary>
    public int? BitLockerProtectionStatus { get; init; }
    public bool BitLockerAccessDenied { get; init; }
    public int? SecureBootEnabled { get; init; }
    public bool? TpmPresent { get; init; }
    /// <summary>1 = TPM 1.2, 2 = TPM 2.0.</summary>
    public int? TpmVersion { get; init; }
    /// <summary>Win32_Tpm IsEnabled/IsActivated initial values; requires administrator.</summary>
    public bool? TpmEnabled { get; init; }
    public bool? TpmActivated { get; init; }
    public int? RunAsPpl { get; init; }
    public int? LsaCfgFlags { get; init; }
    /// <summary>Win32_DeviceGuard.SecurityServicesRunning: 1 Credential Guard, 2 HVCI.</summary>
    public IReadOnlyList<int>? DeviceGuardServicesRunning { get; init; }
    /// <summary>Win32_DeviceGuard.VirtualizationBasedSecurityStatus: 0 off, 1 enabled not running, 2 running.</summary>
    public int? VbsStatus { get; init; }
    public int? VbsRegistryEnabled { get; init; }
    public int? HvciRegistryEnabled { get; init; }
    public int? Smb1 { get; init; }
    public int? WindowsUpdateStart { get; init; }
    /// <summary>Windows Security Center AntiVirusProduct entries (display name, productState); null when unavailable (e.g. Windows Server).</summary>
    public IReadOnlyList<AntivirusProductReading>? AntivirusProducts { get; init; }
}

public sealed record AntivirusProductReading(string Name, int ProductState);

/// <summary>
/// Grades platform posture: an antivirus real-time check from Windows Security Center, then the eight v29
/// firmware_posture.py checks with two corrections:
/// Credential Guard and HVCI prefer the running state from Win32_DeviceGuard over registry configuration, and
/// TPM presence comes from TBS instead of treating "not owned" as "absent". Unreadable values are Unknown, never Finding.
/// </summary>
public static class HardeningPostureEvaluator
{
    public static IReadOnlyList<PostureCheck> Evaluate(PostureReadings r) =>
    [
        Antivirus(r), BitLocker(r), SecureBoot(r), Tpm(r), LsaProtection(r), CredentialGuard(r), VbsHvci(r), Smb1(r), PatchService(r)
    ];

    /// <summary>
    /// Decodes Security Center productState: bits 8-15 are the real-time state (0x10 on, 0x00 off, 0x01/0x11 expired or
    /// snoozed) and bits 0-7 the definitions state (0x00 up to date, 0x10 out of date).
    /// </summary>
    public static (bool RealTimeOn, bool DefinitionsCurrent) DecodeProductState(int productState) =>
        (((productState >> 8) & 0xFF) == 0x10, (productState & 0xFF) == 0x00);

    internal static PostureCheck Antivirus(PostureReadings r)
    {
        const string title = "Antivirus real-time protection";
        if (r.AntivirusProducts is null)
            return Unknown("antivirus", title, "T1562.001", "Windows Security Center is not available on this edition of Windows.");
        if (r.AntivirusProducts.Count == 0)
            return Finding("antivirus", title, "HIGH", "T1562.001", "No antivirus product is registered with Windows Security Center.");
        var states = r.AntivirusProducts.Select(p => (p.Name, State: DecodeProductState(p.ProductState))).ToArray();
        var active = states.Where(p => p.State.RealTimeOn).ToArray();
        var summary = string.Join("; ", states.Select(p => $"{p.Name}: real-time {(p.State.RealTimeOn ? "on" : "off")}, definitions {(p.State.DefinitionsCurrent ? "current" : "out of date")}"));
        if (active.Length == 0)
            return Finding("antivirus", title, "HIGH", "T1562.001", $"No antivirus is protecting this PC in real time ({summary}). Turn on real-time protection in Windows Security or your antivirus.");
        if (active.All(p => !p.State.DefinitionsCurrent))
            return Finding("antivirus", title, "MEDIUM", "T1562.001", $"Real-time protection is on but definitions are out of date ({summary}).");
        return Pass("antivirus", title, "T1562.001", summary);
    }

    internal static PostureCheck BitLocker(PostureReadings r) => r.BitLockerProtectionStatus switch
    {
        1 => Pass("bitlocker", "BitLocker (OS volume)", "T1490", "OS volume protection is on."),
        0 => Finding("bitlocker", "BitLocker (OS volume)", "HIGH", "T1490", "OS volume is not BitLocker-protected; ransomware recovery and offline theft protection are weaker."),
        _ => Unknown("bitlocker", "BitLocker (OS volume)", "T1490", r.BitLockerAccessDenied
            ? "Reading BitLocker status requires administrator rights."
            : "BitLocker status could not be read.")
    };

    internal static PostureCheck SecureBoot(PostureReadings r) => r.SecureBootEnabled switch
    {
        null => Unknown("secure-boot", "UEFI Secure Boot", "T1542", "No Secure Boot state; the system may use legacy BIOS boot."),
        0 => Finding("secure-boot", "UEFI Secure Boot", "MEDIUM", "T1542", "UEFISecureBootEnabled=0; pre-OS bootkits are not blocked."),
        _ => Pass("secure-boot", "UEFI Secure Boot", "T1542", "Secure Boot is enabled.")
    };

    internal static PostureCheck Tpm(PostureReadings r)
    {
        const string title = "Trusted Platform Module";
        if (r.TpmPresent is null) return Unknown("tpm", title, "", "TPM presence could not be determined.");
        if (r.TpmPresent == false) return Finding("tpm", title, "LOW", "", "No TPM was found; BitLocker cannot seal keys in hardware.");
        var version = r.TpmVersion switch { 2 => "TPM 2.0", 1 => "TPM 1.2", _ => "TPM" };
        if (r.TpmEnabled == false || r.TpmActivated == false)
            return Finding("tpm", title, "LOW", "", $"{version} is present but not ready (enabled={Format(r.TpmEnabled)}, activated={Format(r.TpmActivated)}).");
        return Pass("tpm", title, "", r.TpmEnabled is null
            ? $"{version} is present. Readiness requires administrator rights to read."
            : $"{version} is present and ready.");
    }

    internal static PostureCheck LsaProtection(PostureReadings r) => r.RunAsPpl switch
    {
        null => Finding("lsa-ppl", "LSA protection (RunAsPPL)", "HIGH", "T1003", "RunAsPPL is not configured; any administrator process can read LSASS memory."),
        0 => Finding("lsa-ppl", "LSA protection (RunAsPPL)", "HIGH", "T1003", "RunAsPPL=0; credential dumping from LSASS is not blocked."),
        _ => Pass("lsa-ppl", "LSA protection (RunAsPPL)", "T1003", $"RunAsPPL={r.RunAsPpl}.")
    };

    internal static PostureCheck CredentialGuard(PostureReadings r)
    {
        const string title = "Credential Guard";
        if (r.DeviceGuardServicesRunning is { } running)
            return running.Contains(1)
                ? Pass("credential-guard", title, "T1003", "Credential Guard is running.")
                : Finding("credential-guard", title, "LOW", "T1003", $"Credential Guard is not running (LsaCfgFlags={Format(r.LsaCfgFlags)}). Optional hardening recommendation, not a sign of attack.");
        // v29 registry fallback when Device Guard state is unavailable.
        return r.LsaCfgFlags switch
        {
            null => Finding("credential-guard", title, "LOW", "T1003", "LsaCfgFlags is not configured and running state is unavailable; LSASS secrets may not be virtualization-isolated. Optional hardening recommendation."),
            0 => Finding("credential-guard", title, "LOW", "T1003", "LsaCfgFlags=0; Credential Guard is disabled. Optional hardening recommendation, not a sign of attack."),
            _ => Pass("credential-guard", title, "T1003", $"Configured (LsaCfgFlags={r.LsaCfgFlags}); running state unavailable.")
        };
    }

    internal static PostureCheck VbsHvci(PostureReadings r)
    {
        const string title = "VBS / memory integrity (HVCI)";
        if (r.DeviceGuardServicesRunning is { } running)
        {
            if (running.Contains(2)) return Pass("vbs-hvci", title, "", "Memory integrity (HVCI) is running.");
            return r.VbsStatus == 0
                ? Finding("vbs-hvci", title, "LOW", "", "Virtualization-based security is off; kernel exploit mitigations are unavailable.")
                : Finding("vbs-hvci", title, "LOW", "", "Memory integrity (HVCI) is not running; vulnerable driver exploits are less contained.");
        }
        // v29 registry fallback.
        if (r.HvciRegistryEnabled == 1) return Pass("vbs-hvci", title, "", "HVCI is configured (registry); running state unavailable.");
        if (r.VbsRegistryEnabled is null && r.HvciRegistryEnabled is null)
            return Finding("vbs-hvci", title, "LOW", "", "Device Guard registry keys are absent; virtualization-based security is not configured.");
        if (r.HvciRegistryEnabled == 0)
            return Finding("vbs-hvci", title, "LOW", "", "HypervisorEnforcedCodeIntegrity Enabled=0.");
        return Unknown("vbs-hvci", title, "", "VBS is configured but HVCI state could not be determined.");
    }

    internal static PostureCheck Smb1(PostureReadings r) => r.Smb1 switch
    {
        null => Pass("smb1", "SMBv1 server", "T1210", "SMB1 value absent; off by default on Windows 10 1709 and later."),
        0 => Pass("smb1", "SMBv1 server", "T1210", "SMB1=0."),
        _ => Finding("smb1", "SMBv1 server", "HIGH", "T1210", "SMBv1 is enabled; the WannaCry/NotPetya worm path is open.")
    };

    internal static PostureCheck PatchService(PostureReadings r) => r.WindowsUpdateStart switch
    {
        null => Unknown("patch-service", "Windows Update service", "", "wuauserv start type could not be read."),
        4 => Finding("patch-service", "Windows Update service", "HIGH", "", "wuauserv is disabled; security updates will not arrive."),
        _ => Pass("patch-service", "Windows Update service", "", "wuauserv is not disabled.")
    };

    private static string Format(object? value) => value?.ToString()?.ToLowerInvariant() ?? "unknown";

    private static PostureCheck Pass(string id, string title, string technique, string detail) =>
        new(id, title, PostureStates.Pass, "INFO", technique, detail);

    private static PostureCheck Finding(string id, string title, string severity, string technique, string detail) =>
        new(id, title, PostureStates.Finding, severity, technique, detail);

    private static PostureCheck Unknown(string id, string title, string technique, string detail) =>
        new(id, title, PostureStates.Unknown, "INFO", technique, detail);
}
