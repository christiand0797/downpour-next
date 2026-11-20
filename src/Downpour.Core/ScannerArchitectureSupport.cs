namespace Downpour.Core;

public enum ScannerCapability { NativeYaraX, ManagedFallback, Unavailable }

/// <summary>
/// States what the scanner can honestly do on this architecture instead of failing at first use. The YARA-X native
/// module is x64 today; on ARM64 the product must either ship an arm64 module or use a documented managed fallback with
/// fewer rule features. "Unavailable" is a valid answer and must be shown as such rather than reported as a clean scan.
/// </summary>
public static class ScannerArchitectureSupport
{
    public static ScannerCapability Decide(string architecture, bool nativeModulePresent, bool managedFallbackPresent)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(architecture);
        var normalized = architecture.Trim().ToLowerInvariant();
        var supportedNative = normalized is "x64" or "amd64" or "arm64";
        if (supportedNative && nativeModulePresent) return ScannerCapability.NativeYaraX;
        if (managedFallbackPresent) return ScannerCapability.ManagedFallback;
        return ScannerCapability.Unavailable;
    }

    public static string Describe(ScannerCapability capability, string architecture)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(architecture);
        return capability switch
        {
            ScannerCapability.NativeYaraX => $"YARA-X native scanning is available on {architecture}.",
            ScannerCapability.ManagedFallback => $"YARA-X has no module for {architecture}; a reduced managed rule engine is used and rule coverage is limited.",
            _ => $"No rule scanner is available on {architecture}. Scanning is reported as unavailable, never as clean.",
        };
    }
}
