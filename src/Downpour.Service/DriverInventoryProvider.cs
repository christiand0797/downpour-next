using System.Runtime.InteropServices;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Service;

public sealed class DriverInventoryProvider
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

        return new DriverInventorySnapshot(1, DateTimeOffset.UtcNow, totalCount, results, warnings);
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
