using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

/// <summary>
/// Collects read-only platform posture readings from the registry, TPM Base Services, and WMI.
/// No commands or PowerShell are run. Probes that need administrator rights report Unknown when denied.
/// </summary>
public sealed partial class HardeningPostureProvider
{
    private static readonly TimeSpan WmiTimeout = TimeSpan.FromSeconds(5);

    public HardeningPostureSnapshot Capture()
    {
        var warnings = new List<string>();
        var elevated = IsElevated();
        // Win32_EncryptableVolume and Win32_Tpm deny standard users and only fail after their WMI timeout,
        // so skip them when unelevated and report the reading as needing administrator rights.
        var bitLocker = elevated ? ReadBitLocker(warnings) : (null, true);
        var (tpmPresent, tpmVersion) = ReadTpmPresence(warnings);
        var (tpmEnabled, tpmActivated) = elevated && tpmPresent == true ? ReadTpmReadiness() : (null, null);
        var (servicesRunning, vbsStatus) = ReadDeviceGuard(warnings);

        var readings = new PostureReadings
        {
            BitLockerProtectionStatus = bitLocker.Status,
            BitLockerAccessDenied = bitLocker.AccessDenied,
            SecureBootEnabled = ReadDword(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"),
            TpmPresent = tpmPresent,
            TpmVersion = tpmVersion,
            TpmEnabled = tpmEnabled,
            TpmActivated = tpmActivated,
            RunAsPpl = ReadDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"),
            LsaCfgFlags = ReadDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags"),
            DeviceGuardServicesRunning = servicesRunning,
            VbsStatus = vbsStatus,
            VbsRegistryEnabled = ReadDword(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity"),
            HvciRegistryEnabled = ReadDword(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled"),
            Smb1 = ReadDword(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"),
            WindowsUpdateStart = ReadDword(@"SYSTEM\CurrentControlSet\Services\wuauserv", "Start"),
            AntivirusProducts = ReadAntivirusProducts(warnings)
        };

        return new HardeningPostureSnapshot(1, DateTimeOffset.UtcNow, elevated, HardeningPostureEvaluator.Evaluate(readings), warnings);
    }

    private static int? ReadDword(string path, string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return key?.GetValue(name) is int value ? value : null;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static (int? Status, bool AccessDenied) ReadBitLocker(List<string> warnings)
    {
        var drive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        if (!DriveLetter().IsMatch(drive))
        {
            warnings.Add("SystemDrive is not a drive letter; BitLocker status was not queried.");
            return (null, false);
        }
        try
        {
            var value = QueryFirst(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                $"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{drive}'", "ProtectionStatus");
            return (value is null ? null : Convert.ToInt32(value), false);
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            return (null, true);
        }
        catch (Exception ex) when (ex is ManagementException or COMException or TimeoutException)
        {
            warnings.Add($"BitLocker WMI provider unavailable ({ex.GetType().Name}).");
            return (null, false);
        }
    }

    private static (bool? Present, int? Version) ReadTpmPresence(List<string> warnings)
    {
        try
        {
            var info = new TpmDeviceInfo();
            var result = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf<TpmDeviceInfo>(), ref info);
            return result switch
            {
                0 => (true, (int)info.TpmVersion),
                TbsETpmNotFound => (false, null),
                _ => (null, null)
            };
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            warnings.Add("TPM Base Services are unavailable.");
            return (null, null);
        }
    }

    private static (bool? Enabled, bool? Activated) ReadTpmReadiness()
    {
        try
        {
            using var searcher = Searcher(@"root\CIMV2\Security\MicrosoftTpm", "SELECT IsEnabled_InitialValue, IsActivated_InitialValue FROM Win32_Tpm");
            foreach (var item in searcher.Get())
                using (item)
                    return (item["IsEnabled_InitialValue"] as bool?, item["IsActivated_InitialValue"] as bool?);
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException)
        {
            // Win32_Tpm requires administrator rights; readiness stays unknown.
        }
        return (null, null);
    }

    private static (IReadOnlyList<int>? Running, int? VbsStatus) ReadDeviceGuard(List<string> warnings)
    {
        try
        {
            using var searcher = Searcher(@"root\Microsoft\Windows\DeviceGuard",
                "SELECT SecurityServicesRunning, VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard");
            foreach (var item in searcher.Get())
            {
                using (item)
                {
                    var running = item["SecurityServicesRunning"] is uint[] values ? values.Select(v => (int)v).ToArray() : [];
                    var status = item["VirtualizationBasedSecurityStatus"] is uint vbs ? (int?)vbs : null;
                    return (running, status);
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException)
        {
            warnings.Add($"Device Guard state unavailable ({ex.GetType().Name}); using registry configuration.");
        }
        return (null, null);
    }

    /// <summary>Windows Security Center (root\SecurityCenter2) is readable by standard users on client editions.</summary>
    private static IReadOnlyList<AntivirusProductReading>? ReadAntivirusProducts(List<string> warnings)
    {
        try
        {
            using var searcher = Searcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
            var products = new List<AntivirusProductReading>();
            foreach (var item in searcher.Get())
            {
                using (item)
                {
                    var name = item["displayName"] as string;
                    if (string.IsNullOrWhiteSpace(name) || item["productState"] is not uint state || products.Count >= 16) continue;
                    products.Add(new AntivirusProductReading(name.Length > 64 ? name[..64] : name, (int)state));
                }
            }
            return products;
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or TimeoutException)
        {
            warnings.Add($"Windows Security Center is unavailable ({ex.GetType().Name}); antivirus status is unknown.");
            return null;
        }
    }

    private static object? QueryFirst(string scope, string query, string property)
    {
        using var searcher = Searcher(scope, query);
        foreach (var item in searcher.Get())
            using (item)
                return item[property];
        return null;
    }

    private static ManagementObjectSearcher Searcher(string scope, string query) =>
        new(new ManagementScope(scope), new ObjectQuery(query), new System.Management.EnumerationOptions { Timeout = WmiTimeout, ReturnImmediately = false });

    private static bool IsAccessDenied(Exception ex) =>
        ex is UnauthorizedAccessException
        || ex is ManagementException { ErrorCode: ManagementStatus.AccessDenied }
        || ex is COMException { HResult: unchecked((int)0x80070005) };

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [GeneratedRegex("^[A-Za-z]:$")]
    private static partial Regex DriveLetter();

    private const uint TbsETpmNotFound = 0x8028400F;

    [StructLayout(LayoutKind.Sequential)]
    private struct TpmDeviceInfo
    {
        public uint StructVersion;
        public uint TpmVersion;
        public uint TpmInterfaceType;
        public uint TpmImpRevision;
    }

    [DllImport("tbs.dll")]
    private static extern uint Tbsi_GetDeviceInfo(uint size, ref TpmDeviceInfo info);
}
