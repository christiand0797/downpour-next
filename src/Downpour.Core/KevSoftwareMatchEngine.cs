using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed record KevSoftwareCandidate(
    string CveId,
    string Vendor,
    string Product,
    string VulnerabilityName,
    DateOnly DateAdded,
    string InstalledName,
    string InstalledVersion,
    string InstalledPublisher);

/// <summary>Produces cautious product-name leads only. The KEV catalog has no local affected-version proof.</summary>
public static class KevSoftwareMatchEngine
{
    public const int MaximumCandidates = 250;
    private static readonly HashSet<string> GenericProducts = new(StringComparer.Ordinal)
    {
        "core", "server", "desktop", "runtime", "enterprise", "standard", "professional", "pro",
        "agent", "client", "platform", "suite", "manager", "viewer", "service", "sdk", "extension",
        "security update", "operating system", "application", "framework", "web application"
    };

    public static IReadOnlyList<KevSoftwareCandidate> FindCandidates(
        IReadOnlyList<InstalledSoftwareEntry> installed,
        IReadOnlyList<KevEntry> catalog,
        out bool wasLimited)
    {
        ArgumentNullException.ThrowIfNull(installed);
        ArgumentNullException.ThrowIfNull(catalog);
        if (installed.Count > 2000 || catalog.Count > KevCatalogClient.MaximumEntries)
            throw new ArgumentOutOfRangeException(nameof(installed), "Software or catalog input exceeds the supported bound.");

        wasLimited = false;
        var inventory = installed.Select(entry => new
        {
            Entry = entry,
            Name = Normalize(entry.Name),
            Publisher = Normalize(entry.Publisher)
        }).Where(item => item.Name.Length > 0).ToArray();
        var candidates = new List<KevSoftwareCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var kev in catalog.OrderByDescending(entry => entry.DateAdded).ThenBy(entry => entry.CveId, StringComparer.Ordinal))
        {
            var vendor = Normalize(kev.Vendor);
            var product = Normalize(kev.Product);
            if (!IsMeaningfulProduct(product) || vendor.Length == 0 || product == vendor) continue;
            foreach (var item in inventory)
            {
                var vendorMatches = ContainsPhrase(item.Publisher, vendor) || ContainsPhrase(item.Name, vendor);
                if (!vendorMatches || !EndsWithProductName(item.Name, product)) continue;
                var key = $"{kev.CveId}\u001f{item.Entry.Name}\u001f{item.Entry.Version}";
                if (!seen.Add(key)) continue;
                if (candidates.Count >= MaximumCandidates) { wasLimited = true; return candidates; }
                candidates.Add(new KevSoftwareCandidate(kev.CveId, kev.Vendor, kev.Product, kev.VulnerabilityName,
                    kev.DateAdded, item.Entry.Name, item.Entry.Version, item.Entry.Publisher));
            }
        }
        return candidates;
    }

    private static bool IsMeaningfulProduct(string product) =>
        product.Length >= 4 && !GenericProducts.Contains(product) &&
        !product.Split(' ', StringSplitOptions.RemoveEmptyEntries).All(GenericProducts.Contains);

    private static bool ContainsPhrase(string value, string phrase) =>
        value.Length > 0 && phrase.Length > 0 && $" {value} ".Contains($" {phrase} ", StringComparison.Ordinal);

    // Requiring the product at the end avoids treating a related application's leading word
    // (for example, "Chrome Remote Desktop") as proof of the browser product itself.
    private static bool EndsWithProductName(string applicationName, string product) =>
        applicationName.Equals(product, StringComparison.Ordinal) ||
        applicationName.EndsWith($" {product}", StringComparison.Ordinal);

    private static string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var builder = new StringBuilder(Math.Min(value.Length, 512));
        var needsSpace = false;
        foreach (var character in value.Trim())
        {
            if (char.IsLetterOrDigit(character))
            {
                if (needsSpace && builder.Length > 0) builder.Append(' ');
                builder.Append(char.ToLowerInvariant(character));
                needsSpace = false;
            }
            else
            {
                needsSpace = true;
            }
            if (builder.Length >= 512) break;
        }
        return builder.ToString();
    }
}
