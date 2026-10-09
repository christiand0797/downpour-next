namespace Downpour.Core;

/// <summary>A KEV record judged against this PC.</summary>
public sealed record CveAssessment(KevEntry Entry, bool IsWindows, bool LikelyMissingOnThisPc, IReadOnlyList<string> InstalledMatches);

/// <summary>
/// Relates the CISA Known Exploited Vulnerabilities catalog to this PC without claiming proof:
/// a Windows component flaw published to KEV after the newest installed update, with a CVE year no more than a year
/// older than that update, is "likely missing"; installed applications are matched by product name only.
/// </summary>
public static class CveExposure
{
    /// <summary>Microsoft products that ship inside Windows itself (KEV names them inconsistently).</summary>
    private static readonly string[] WindowsComponents =
        ["Windows", "Win32k", "Internet Explorer", "MSHTML", "SMBv1", "Server Message Block", "DirectX", "Kernel", "Print Spooler", "Remote Desktop", "Hyper-V", "Defender"];

    public static bool IsWindows(KevEntry entry) =>
        entry.Vendor.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) &&
        WindowsComponents.Any(c => entry.Product.Contains(c, StringComparison.OrdinalIgnoreCase) || entry.VulnerabilityName.Contains($"Windows {c}", StringComparison.OrdinalIgnoreCase));

    public static int CveYear(string cveId) =>
        cveId.Length > 8 && int.TryParse(cveId.AsSpan(4, 4), out var year) ? year : 0;

    public static bool LikelyMissing(KevEntry entry, DateTimeOffset? lastUpdateUtc) =>
        lastUpdateUtc is { } last && IsWindows(entry) &&
        entry.DateAdded > DateOnly.FromDateTime(last.UtcDateTime) && CveYear(entry.CveId) >= last.Year - 1;

    public static IReadOnlyList<CveAssessment> Assess(IReadOnlyList<KevEntry> catalog, DateTimeOffset? lastUpdateUtc, IReadOnlyList<KevSoftwareCandidate> candidates)
    {
        var installed = candidates.GroupBy(c => c.CveId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(c => $"{c.InstalledName} {c.InstalledVersion}".Trim()).Distinct().Take(5).ToArray(), StringComparer.OrdinalIgnoreCase);
        return catalog
            .Select(e => new CveAssessment(e, IsWindows(e), LikelyMissing(e, lastUpdateUtc), installed.GetValueOrDefault(e.CveId) ?? []))
            .OrderByDescending(a => a.Entry.DateAdded).ThenByDescending(a => a.Entry.CveId, StringComparer.Ordinal)
            .ToArray();
    }

    public static string NvdUrl(string cveId) => $"https://nvd.nist.gov/vuln/detail/{Uri.EscapeDataString(cveId)}";

    public static string? MicrosoftUrl(KevEntry entry) =>
        entry.Vendor.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) ? $"https://msrc.microsoft.com/update-guide/vulnerability/{Uri.EscapeDataString(entry.CveId)}" : null;
}
