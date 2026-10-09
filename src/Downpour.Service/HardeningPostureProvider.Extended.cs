using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

/// <summary>Read-only registry and WMI readings for the extended hardening checks. Nothing is changed and no command is run.</summary>
public sealed partial class HardeningPostureProvider
{
    private static PostureReadings ReadExtended(PostureReadings readings, List<string> warnings)
    {
        const string lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";
        const string system = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        const string version = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        var winlogon = $@"{version}\Winlogon";
        var (guest, admin) = ReadBuiltInAccounts(warnings);
        return readings with
        {
            Defender = ReadDefender(readings, warnings),
            FirewallProfiles = ReadFirewallProfiles(),
            EnableLua = ReadDword(system, "EnableLUA"),
            ConsentPromptBehaviorAdmin = ReadDword(system, "ConsentPromptBehaviorAdmin"),
            PromptOnSecureDesktop = ReadDword(system, "PromptOnSecureDesktop"),
            DenyTsConnections = ReadDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"),
            RdpUserAuthentication = ReadDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication"),
            RemoteAssistanceAllowed = ReadDword(@"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp"),
            NoDriveTypeAutoRun = ReadDword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
                ?? ReadUserDword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"),
            PowerShellExecutionPolicy = ReadString(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy")
                ?? ReadString(@"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy"),
            PowerShell2Installed = OptionalFeatureEnabled("MicrosoftWindowsPowerShellV2"),
            ScriptBlockLogging = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"),
            GuestEnabled = guest,
            BuiltInAdministratorEnabled = admin,
            LlmnrEnabled = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"),
            NetbiosEnabledInterfaces = CountNetbiosInterfaces(),
            WDigestUseLogonCredential = ReadDword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
            NoLmHash = ReadDword(lsa, "NoLMHash"),
            LmCompatibilityLevel = ReadDword(lsa, "LmCompatibilityLevel"),
            RestrictAnonymousSam = ReadDword(lsa, "RestrictAnonymousSAM"),
            SmbServerRequireSigning = ReadDword(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature"),
            Smb1ClientStart = ReadDword(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"),
            PointAndPrintNoWarningNoElevation = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "NoWarningNoElevationOnInstall"),
            SpoolerStart = ReadDword(@"SYSTEM\CurrentControlSet\Services\Spooler", "Start"),
            RemoteRegistryStart = ReadDword(@"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start"),
            WinRmStart = ReadDword(@"SYSTEM\CurrentControlSet\Services\WinRM", "Start"),
            SmartScreen = ReadString(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"),
            SmartScreenPolicy = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"),
            VulnerableDriverBlocklist = ReadDword(@"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable"),
            // Only the presence of a stored password is checked; its value is never read.
            AutoLogonWithStoredPassword = ReadString(winlogon, "AutoAdminLogon") == "1" && ValueExists(winlogon, "DefaultPassword"),
            // Feature and Insider builds install as a new Windows build without a KB entry; InstallDate is that build's install time.
            LastUpdateInstalled = Newest(ReadLastUpdate(warnings), ReadDword(version, "InstallDate") is int unix and > 0 ? DateTimeOffset.FromUnixTimeSeconds((uint)unix) : null),
            OsBuild = int.TryParse(ReadString(version, "CurrentBuild"), NumberStyles.None, CultureInfo.InvariantCulture, out var build) ? build : null,
            OsRevision = ReadDword(version, "UBR"),
            OsDisplayVersion = Bounded(ReadString(version, "DisplayVersion"), 16),
            OsEdition = Bounded(ReadString(version, "EditionID"), 32),
            InsiderBranch = Bounded(ReadString(@"SOFTWARE\Microsoft\WindowsSelfHost\Applicability", "BranchName"), 32),
        };
    }

    private static DateTimeOffset? Newest(DateTimeOffset? a, DateTimeOffset? b) => a is null ? b : b is null ? a : a > b ? a : b;

    private static string? Bounded(string? value, int max) => value is null ? null : value.Length <= max ? value : value[..max];

    private static string? ReadString(string path, string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return key?.GetValue(name) is string value ? value.Trim() : null;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    private static int? ReadUserDword(string path, string name)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            return key?.GetValue(name) is int value ? value : null;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    private static bool ValueExists(string path, string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return key?.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase) == true;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException) { return false; }
    }

    private static IReadOnlyDictionary<string, int?> ReadFirewallProfiles()
    {
        const string standard = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        const string policy = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        return new Dictionary<string, int?>
        {
            ["Domain"] = ReadDword($@"{policy}\DomainProfile", "EnableFirewall") ?? ReadDword($@"{standard}\DomainProfile", "EnableFirewall"),
            ["Private"] = ReadDword($@"{policy}\PrivateProfile", "EnableFirewall") ?? ReadDword($@"{standard}\StandardProfile", "EnableFirewall"),
            ["Public"] = ReadDword($@"{policy}\PublicProfile", "EnableFirewall") ?? ReadDword($@"{standard}\PublicProfile", "EnableFirewall"),
        };
    }

    private static int? CountNetbiosInterfaces()
    {
        try
        {
            using var interfaces = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces");
            if (interfaces is null) return 0;
            var count = 0;
            foreach (var name in interfaces.GetSubKeyNames().Take(64))
            {
                using var item = interfaces.OpenSubKey(name);
                if (item?.GetValue("NetbiosOptions") is int option && option != 2) count++;
            }
            return count;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    private static bool OptionalFeatureEnabled(string feature)
    {
        try
        {
            // Feature names are fixed constants above, never caller input.
            return QueryFirst(@"root\CIMV2", $"SELECT InstallState FROM Win32_OptionalFeature WHERE Name = '{feature}'", "InstallState") is uint state && state == 1;
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException) { return false; }
    }

    private static (bool? Guest, bool? Administrator) ReadBuiltInAccounts(List<string> warnings)
    {
        try
        {
            bool? guest = null, admin = null;
            using var searcher = Searcher(@"root\CIMV2", "SELECT SID, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE");
            foreach (var item in searcher.Get())
            {
                using (item)
                {
                    if (item["SID"] is not string sid || item["Disabled"] is not bool disabled) continue;
                    if (sid.EndsWith("-501", StringComparison.Ordinal)) guest = !disabled;
                    else if (sid.EndsWith("-500", StringComparison.Ordinal)) admin = !disabled;
                }
            }
            return (guest, admin);
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException)
        {
            warnings.Add($"Local account state unavailable ({ex.GetType().Name}).");
            return (null, null);
        }
    }

    /// <summary>Newest Win32_QuickFixEngineering InstalledOn date (formats vary: M/d/yyyy, yyyyMMdd or a hex FILETIME).</summary>
    private static DateTimeOffset? ReadLastUpdate(List<string> warnings)
    {
        try
        {
            DateTimeOffset? newest = null;
            using var searcher = Searcher(@"root\CIMV2", "SELECT InstalledOn FROM Win32_QuickFixEngineering");
            var seen = 0;
            foreach (var item in searcher.Get())
            {
                using (item)
                {
                    if (++seen > 2048) break;
                    if (ParseInstalledOn(item["InstalledOn"] as string) is { } date && (newest is null || date > newest)) newest = date;
                }
            }
            return newest;
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException)
        {
            warnings.Add($"Installed update history unavailable ({ex.GetType().Name}).");
            return null;
        }
    }

    public static DateTimeOffset? ParseInstalledOn(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim();
        string[] formats = ["M/d/yyyy", "MM/dd/yyyy", "yyyyMMdd", "d/M/yyyy"];
        if (DateTime.TryParseExact(value, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date))
            return date > DateTime.UtcNow.AddDays(2) ? null : new DateTimeOffset(date, TimeSpan.Zero);
        if (value.Length is > 8 and <= 16 && long.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var fileTime) && fileTime > 0)
        {
            try { return DateTimeOffset.FromFileTime(fileTime).ToUniversalTime(); }
            catch (ArgumentOutOfRangeException) { return null; }
        }
        return null;
    }

    private static DefenderReading? ReadDefender(PostureReadings readings, List<string> warnings)
    {
        const string scope = @"root\Microsoft\Windows\Defender";
        try
        {
            string? mode = null;
            bool? realTime = null, tamper = null;
            int? age = null;
            using (var status = Searcher(scope, "SELECT AMRunningMode, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureAge FROM MSFT_MpComputerStatus"))
            {
                foreach (var item in status.Get())
                {
                    using (item)
                    {
                        mode = item["AMRunningMode"] as string;
                        realTime = item["RealTimeProtectionEnabled"] as bool?;
                        tamper = item["IsTamperProtected"] as bool?;
                        age = item["AntivirusSignatureAge"] is uint a ? (int)Math.Min(a, 9999) : null;
                    }
                    break;
                }
            }
            var primary = mode is null ? (bool?)null : mode.Equals("Normal", StringComparison.OrdinalIgnoreCase);
            int? maps = null, samples = null, pua = null, folders = null, network = null, asr = null;
            try
            {
                using var preference = Searcher(scope, "SELECT MAPSReporting, SubmitSamplesConsent, PUAProtection, EnableControlledFolderAccess, EnableNetworkProtection, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference");
                foreach (var item in preference.Get())
                {
                    using (item)
                    {
                        maps = Number(item["MAPSReporting"]);
                        samples = Number(item["SubmitSamplesConsent"]);
                        pua = Number(item["PUAProtection"]);
                        folders = Number(item["EnableControlledFolderAccess"]);
                        network = Number(item["EnableNetworkProtection"]);
                        asr = item["AttackSurfaceReductionRules_Actions"] is byte[] actions ? actions.Count(a => a is 1 or 2 or 6) : 0;
                    }
                    break;
                }
            }
            catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException)
            {
                warnings.Add("Some Microsoft Defender settings need administrator rights to read.");
            }
            return new DefenderReading(primary, realTime, tamper, age, maps, samples, pua, folders, network, asr);
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException)
        {
            // Defender's provider is gone when another antivirus replaced it; Security Center tells us that.
            var otherActive = readings.AntivirusProducts?.Any(p => !p.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase)
                && HardeningPostureEvaluator.DecodeProductState(p.ProductState).RealTimeOn) == true;
            return otherActive ? new DefenderReading(false, null, null, null, null, null, null, null, null, null) : null;
        }
    }

    private static int? Number(object? value) => value switch
    {
        byte b => b, sbyte sb => sb, short s => s, ushort us => us, int i => i, uint u => (int)Math.Min(u, int.MaxValue), _ => null,
    };
}
