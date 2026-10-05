using Microsoft.Win32;
using System.Security;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Reads bounded uninstall-key display metadata only; it never reads install paths or uninstall commands.</summary>
public sealed class InstalledSoftwareInventoryProvider
{
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const int MaximumRows = 1000;
    private const int MaximumKeysInspected = 20_000;
    private const int MaximumTextLength = 160;

    public InstalledSoftwareSnapshot Capture()
    {
        var rows = new Dictionary<string, InstalledSoftwareEntry>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        var inspected = 0;
        var truncated = false;
        var views = Environment.Is64BitOperatingSystem
            ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
            : new[] { RegistryView.Registry32 };

        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        foreach (var view in views)
        {
            if (inspected >= MaximumKeysInspected) { truncated = true; break; }
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var uninstall = root.OpenSubKey(UninstallKey, writable: false);
                if (uninstall is null) continue;
                foreach (var subKeyName in uninstall.GetSubKeyNames())
                {
                    if (++inspected > MaximumKeysInspected) { truncated = true; break; }
                    try
                    {
                        using var product = uninstall.OpenSubKey(subKeyName, writable: false);
                        if (product is null || IsSystemComponent(product)) continue;
                        var name = SafeText(product.GetValue("DisplayName", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string);
                        if (name.Length == 0) continue;
                        var version = SafeText(product.GetValue("DisplayVersion", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string);
                        var publisher = SafeText(product.GetValue("Publisher", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string);
                        var scope = hive == RegistryHive.LocalMachine ? "Machine" : "Current user";
                        var row = new InstalledSoftwareEntry(name, version, publisher, scope);
                        var key = $"{name}\u001f{version}\u001f{publisher}";
                        rows.TryAdd(key, row);
                    }
                    catch (Exception exception) when (IsExpectedRegistryFailure(exception))
                    {
                        AddWarning(warnings, "Some uninstall registry entries could not be read.");
                    }
                }
            }
            catch (Exception exception) when (IsExpectedRegistryFailure(exception))
            {
                AddWarning(warnings, hive == RegistryHive.LocalMachine
                    ? "Machine software inventory is partially inaccessible."
                    : "Current-user software inventory is partially inaccessible.");
            }
        }

        var ordered = rows.Values.OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase).ThenBy(row => row.Version, StringComparer.OrdinalIgnoreCase).ToArray();
        if (truncated) AddWarning(warnings, $"Registry scanning stopped at {MaximumKeysInspected:N0} keys.");
        if (ordered.Length > MaximumRows)
        {
            AddWarning(warnings, $"Software display is limited to {MaximumRows:N0} of {ordered.Length:N0} discovered entries.");
            ordered = ordered.Take(MaximumRows).ToArray();
        }
        if (ordered.Length == 0 && warnings.Count == 0) AddWarning(warnings, "No uninstall-key application entries were available.");
        return new InstalledSoftwareSnapshot(1, DateTimeOffset.UtcNow, warnings.Count == 0 ? "Available" : "Partial",
            rows.Count, ordered, warnings);
    }

    private static bool IsSystemComponent(RegistryKey key)
    {
        try { return key.GetValue("SystemComponent", 0, RegistryValueOptions.DoNotExpandEnvironmentNames) is int value && value == 1; }
        catch (Exception exception) when (IsExpectedRegistryFailure(exception)) { return false; }
    }

    private static string SafeText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var normalized = new string(value.Trim().Where(character => !char.IsControl(character)).ToArray());
        return normalized.Length <= MaximumTextLength ? normalized : normalized[..MaximumTextLength];
    }

    private static bool IsExpectedRegistryFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or SecurityException or ArgumentException;

    private static void AddWarning(List<string> warnings, string warning)
    {
        if (warnings.Count < 16 && !warnings.Contains(warning, StringComparer.Ordinal)) warnings.Add(warning);
    }
}
