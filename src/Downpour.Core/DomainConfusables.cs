using System.Globalization;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed record DomainAssessment(
    string Domain,
    string AsciiForm,
    string Scripts,
    bool MixedScript,
    IReadOnlyList<string> LookalikeBrands,
    string Verdict)
{
    /// <summary>True when the name contains a character outside ASCII, even if it folds to one script.</summary>
    public bool NonAscii { get; init; }
}

/// <summary>
/// Catches lookalike domains that ordinary string checks and many reputation lists miss. A Cyrillic "а" in a bank name
/// is a different domain, so it is not blocked by name, and it is not yet in any blocklist. The decoded form is always
/// shown next to the original, and a match is reported as context for a finding, never as a block decision.
/// </summary>
public static class DomainConfusables
{
    private static readonly Dictionary<char, char> Confusables = new()
    {
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c', ['у'] = 'y', ['і'] = 'i', ['ј'] = 'j',
        ['ѕ'] = 's', ['һ'] = 'h', ['ԁ'] = 'd', ['ԛ'] = 'q', ['ԝ'] = 'w', ['ӏ'] = 'l', ['ο'] = 'o', ['α'] = 'a',
        ['ν'] = 'v', ['ρ'] = 'p', ['τ'] = 't', ['ι'] = 'i', ['κ'] = 'k', ['μ'] = 'u', ['ѵ'] = 'v', ['ү'] = 'y',
        ['ɡ'] = 'g', ['ı'] = 'i', ['ɑ'] = 'a', ['ɩ'] = 'i', ['ℓ'] = 'l',
    };

    private static readonly (string Name, string Domain)[] ProtectedBrands =
    [
        ("Microsoft", "microsoft"), ("Microsoft", "office"), ("Google", "google"), ("Google", "gmail"),
        ("Apple", "apple"), ("Apple", "icloud"), ("PayPal", "paypal"), ("Amazon", "amazon"),
        ("Steam", "steamcommunity"), ("Discord", "discord"), ("Netflix", "netflix"), ("Facebook", "facebook"),
        ("Instagram", "instagram"), ("WhatsApp", "whatsapp"), ("Dropbox", "dropbox"), ("GitHub", "github"),
    ];

    public static DomainAssessment Assess(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        var trimmed = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (trimmed.Length > 253) throw new ArgumentOutOfRangeException(nameof(domain));
        var unicode = Decode(trimmed);
        var scripts = ScriptsOf(unicode);
        var mixed = scripts.Count(script => script != "Common") > 1;
        var folded = Fold(unicode);
        var label = unicode.Split('.')[0];
        var foldedLabel = folded.Split('.')[0];
        var brands = ProtectedBrands
            .Where(brand => !string.Equals(label, brand.Domain, StringComparison.Ordinal) &&
                            (string.Equals(foldedLabel, brand.Domain, StringComparison.Ordinal) ||
                             stripWww(foldedLabel) == brand.Domain || folded.Contains(brand.Domain, StringComparison.Ordinal) && !IsAsciiExact(trimmed, brand.Domain)))
            .Select(brand => brand.Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var verdict = brands.Length > 0
            ? $"Lookalike of {string.Join(", ", brands)}: the decoded name resembles a protected brand but the domain differs."
            : mixed ? "Mixed-script domain: legitimate brands do not usually mix writing systems in one name."
            : HasNonAscii(unicode) ? "Non-ASCII domain. Decoded form shown; legitimate for many sites, so compare it carefully."
            : "Plain ASCII domain; no lookalike detected.";
        return new DomainAssessment(trimmed, folded, scripts.Count == 0 ? "Common" : string.Join(", ", scripts), mixed, brands, verdict)
        {
            NonAscii = HasNonAscii(unicode),
        };
    }

    /// <summary>
    /// Bounded assessment for an inventory path: a hostile cache name is ignored rather than failing the capture, and a
    /// plain ASCII name with no lookalike returns null so ordinary entries carry no extra payload. The result is context
    /// for a person, never a block decision.
    /// </summary>
    public static DomainLookalike? Describe(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return null;
        var trimmed = domain.Trim();
        if (trimmed.Length > 253) return null;
        DomainAssessment assessment;
        try
        {
            assessment = Assess(trimmed);
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (!assessment.NonAscii && !assessment.MixedScript && assessment.LookalikeBrands.Count == 0) return null;
        var decoded = assessment.AsciiForm.Length <= 512 ? assessment.AsciiForm : assessment.AsciiForm[..512];
        return new DomainLookalike(decoded, assessment.Scripts, assessment.MixedScript, assessment.LookalikeBrands, assessment.Verdict);
    }

    private static string Decode(string domain)
    {
        try { return new IdnMapping().GetUnicode(domain); }
        catch (ArgumentException) { return domain; }
    }

    private static string Fold(string unicode) =>
        new(unicode.Select(character => Confusables.GetValueOrDefault(character, character)).ToArray());

    private static bool HasNonAscii(string value) => value.Any(character => character > 0x7f);

    private static bool IsAsciiExact(string original, string brand) => original.Contains(brand, StringComparison.Ordinal);

    private static string stripWww(string value) => value.StartsWith("www.", StringComparison.Ordinal) ? value[4..] : value;

    private static IReadOnlyList<string> ScriptsOf(string value)
    {
        var scripts = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var character in value)
        {
            if (character is '.' or '-' or >= '0' and <= '9') continue;
            scripts.Add(character switch
            {
                >= '\u0400' and <= '\u04FF' => "Cyrillic",
                >= '\u0370' and <= '\u03FF' => "Greek",
                >= '\u0590' and <= '\u05FF' => "Hebrew",
                >= '\u0600' and <= '\u06FF' => "Arabic",
                >= '\u0900' and <= '\u097F' => "Devanagari",
                >= '\u0E00' and <= '\u0E7F' => "Thai",
                >= '\u3040' and <= '\u30FF' => "Japanese",
                >= '\u4E00' and <= '\u9FFF' => "Han",
                >= '\uAC00' and <= '\uD7AF' => "Hangul",
                >= '\u0250' and <= '\u02AF' => "IPA extensions",
                < '\u0080' => "Latin",
                _ => "Other",
            });
        }
        return scripts.ToArray();
    }
}
