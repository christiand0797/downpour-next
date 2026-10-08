using System.Runtime.InteropServices;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>
/// Loaded kernel drivers with their location and signature (embedded Authenticode or Windows catalog, through the
/// shared cached <see cref="FileSignatureChecker"/>, so unchanged drivers are checked once).
/// </summary>
public sealed class DriverInventoryProvider(FileSignatureChecker? signatures = null)
{
    private const int MaximumDrivers = 512;
    private const int MaximumTextLength = 512;

    public DriverInventorySnapshot Capture()
    {
        var warnings = new List<string>();
        if (!EnumDeviceDrivers([], 0, out var requiredBytes))
        {
            warnings.Add("Windows did not return the loaded kernel driver list.");
            return Empty(warnings);
        }

        if (requiredBytes <= 0)
        {
            warnings.Add("No driver bases were returned. Driver enumeration may require additional system access.");
            return Empty(warnings);
        }

        var availableCount = Math.Min(requiredBytes / IntPtr.Size, MaximumDrivers);
        var imageBases = new IntPtr[availableCount];
        if (!EnumDeviceDrivers(imageBases, checked(availableCount * IntPtr.Size), out var refreshedBytes))
        {
            warnings.Add("Windows could not read the loaded kernel driver list.");
            return Empty(warnings);
        }

        var totalCount = Math.Max(0, refreshedBytes / IntPtr.Size);
        if (totalCount > MaximumDrivers) warnings.Add($"Driver display is limited to the first {MaximumDrivers} of {totalCount} loaded entries.");

        var windowsRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\', '/');
        var systemDrivers = $"{windowsRoot}\\system32\\drivers";
        var results = new List<DriverInventoryEntry>(Math.Min(totalCount, MaximumDrivers));
        for (var index = 0; index < Math.Min(totalCount, imageBases.Length); index++)
        {
            if (imageBases[index] == IntPtr.Zero) continue;
            var nameBuffer = new StringBuilder(MaximumTextLength);
            if (GetDeviceDriverBaseName(imageBases[index], nameBuffer, nameBuffer.Capacity) == 0) continue;
            var pathBuffer = new StringBuilder(MaximumTextLength);
            _ = GetDeviceDriverFileName(imageBases[index], pathBuffer, pathBuffer.Capacity);
            var name = Bound(nameBuffer.ToString());
            var imagePath = Bound(pathBuffer.ToString());
            var normalizedPath = imagePath.Replace('/', '\\');
            var inSystemDrivers = normalizedPath.StartsWith(systemDrivers, StringComparison.OrdinalIgnoreCase) ||
                                  normalizedPath.StartsWith("\\SystemRoot\\System32\\drivers", StringComparison.OrdinalIgnoreCase);
            var userWritable = normalizedPath.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase) ||
                               normalizedPath.Contains("\\appdata\\", StringComparison.OrdinalIgnoreCase) ||
                               normalizedPath.Contains("\\downloads\\", StringComparison.OrdinalIgnoreCase) ||
                               normalizedPath.Contains("\\users\\public\\", StringComparison.OrdinalIgnoreCase);
            results.Add(new DriverInventoryEntry(name, imagePath, inSystemDrivers, userWritable));
        }

        // Windows 11 24H2 and later hide kernel image bases from processes without SeDebugPrivilege, so every base comes
        // back zero and nothing above can be named. Fall back to the running driver services, which standard users may read.
        if (results.Count == 0 && totalCount > 0)
        {
            var running = RunningDriverServices(warnings);
            if (running.Count > 0)
            {
                warnings.Add($"Windows hides kernel module addresses from standard accounts; showing the {running.Count:N0} running driver services instead of all {totalCount:N0} loaded modules.");
                return new DriverInventorySnapshot(1, DateTimeOffset.UtcNow, totalCount, WithSignatures(running.Take(MaximumDrivers)), warnings);
            }
            warnings.Add("Windows hid every loaded kernel module from this account and the driver service list was unavailable.");
        }

        return new DriverInventorySnapshot(1, DateTimeOffset.UtcNow, totalCount, WithSignatures(results), warnings);
    }

    /// <summary>Running kernel and file-system driver services from WMI Win32_SystemDriver (documented, read-only).</summary>
    private static List<DriverInventoryEntry> RunningDriverServices(List<string> warnings)
    {
        var entries = new List<DriverInventoryEntry>();
        var windowsRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\', '/');
        var systemDrivers = $@"{windowsRoot}\system32\drivers";
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(@"root\cimv2",
                "SELECT Name, PathName FROM Win32_SystemDriver WHERE State = 'Running'",
                new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(15), ReturnImmediately = true, Rewindable = false });
            foreach (var item in searcher.Get())
            {
                using (item)
                {
                    if (entries.Count >= MaximumDrivers) break;
                    var service = item["Name"] as string ?? "";
                    var path = Bound(item["PathName"] as string ?? "").Trim('"');
                    if (service.Length == 0) continue;
                    var name = Bound(path.Length > 0 ? Path.GetFileName(path) : service);
                    var normalized = path.Replace('/', '\\');
                    var inSystemDrivers = normalized.StartsWith(systemDrivers, StringComparison.OrdinalIgnoreCase);
                    var userWritable = normalized.Contains(@"\temp\", StringComparison.OrdinalIgnoreCase) ||
                                       normalized.Contains(@"\appdata\", StringComparison.OrdinalIgnoreCase) ||
                                       normalized.Contains(@"\downloads\", StringComparison.OrdinalIgnoreCase) ||
                                       normalized.Contains(@"\users\public\", StringComparison.OrdinalIgnoreCase);
                    entries.Add(new DriverInventoryEntry(name, path, inSystemDrivers, userWritable));
                }
            }
        }
        catch (Exception ex) when (ex is System.Management.ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            warnings.Add("Windows Management Instrumentation did not return the running driver list.");
        }
        return entries;
    }

    private IReadOnlyList<DriverInventoryEntry> WithSignatures(IEnumerable<DriverInventoryEntry> drivers)
    {
        if (signatures is null) return drivers.ToArray();
        return drivers.Select(driver =>
        {
            if (ThreatDatabaseService.DriverPath(driver.ImagePath) is not { } path || signatures.Check(path) is not { } signature) return driver;
            var signer = signature.Signer is { Length: > 0 } s ? Bound(s) : null;
            return driver with { Signed = signature.Signed, Signer = signer, MicrosoftSigned = signature.Signed == true && signature.Microsoft };
        }).ToArray();
    }

    private static DriverInventorySnapshot Empty(IReadOnlyList<string> warnings) =>
        new(1, DateTimeOffset.UtcNow, 0, [], warnings);

    private static string Bound(string value) => value.Length <= MaximumTextLength ? value : value[..MaximumTextLength];

    [DllImport("psapi.dll", SetLastError = true, EntryPoint = "EnumDeviceDrivers")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDeviceDrivers([Out] IntPtr[] imageBases, int bufferBytes, out int bytesNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, EntryPoint = "GetDeviceDriverBaseNameW")]
    private static extern int GetDeviceDriverBaseName(IntPtr imageBase, StringBuilder baseName, int size);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, EntryPoint = "GetDeviceDriverFileNameW")]
    private static extern int GetDeviceDriverFileName(IntPtr imageBase, StringBuilder fileName, int size);
}
