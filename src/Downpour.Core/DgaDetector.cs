using System.Text.RegularExpressions;

namespace Downpour.Core;

public sealed record DgaScoreResult(
    string Domain,
    int Score,
    double Entropy,
    double ConsonantRatio,
    double DigitRatio,
    double BigramScore,
    bool IsDga,
    double Confidence,
    IReadOnlyList<string> Factors);

public static class DgaDetector
{
    public const int AlertThreshold = 70;
    public const int HighThreshold = 85;

    public static readonly string[] KnownGoodSuffixes =
    [
        ".microsoft.com", ".microsoftonline.com", ".windows.com", ".windowsupdate.com", ".msn.com",
        ".office.com", ".office365.com", ".outlook.com", ".live.com",
        ".azure.com", ".azureedge.net", ".azurewebsites.net",
        ".google.com", ".googleapis.com", ".gstatic.com",
        ".googleusercontent.com", ".cloudflare.com", ".cloudflareclient.com",
        ".amazonaws.com", ".akamai.com", ".akamaiedge.net", ".akamaihd.net",
        ".edgekey.net", ".apple.com", ".icloud.com", ".cdn.mozilla.net",
        ".steampowered.com", ".riotgames.com", ".battle.net", ".nvidia.com",
        ".intel.com", ".amd.com", ".dell.com", ".hp.com", ".lenovo.com",
        ".asus.com", ".msi.com", ".gigabyte.com", ".spotify.com",
        ".netflix.com", ".youtube.com", ".github.com",
        ".githubusercontent.com", ".pypi.org", ".python.org", ".npmjs.org",
        ".docker.com", ".docker.io", ".ubuntu.com", ".debian.org",
        ".norton.com", ".mcafee.com", ".kaspersky.com", ".avast.com",
        ".bitdefender.com", ".eset.com", ".virustotal.com", ".abuse.ch"
    ];

    public static readonly HashSet<string> RiskyTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click",
        "link", "fit", "rest", "cam", "quest", "cfd", "sbs"
    };

    private static readonly HashSet<string> CommonBigrams = new(StringComparer.OrdinalIgnoreCase)
    {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar"
    };

    private static readonly string[] CommonWords =
    [
        "www", "mail", "ftp", "api", "cdn", "static", "assets", "media",
        "blog", "shop", "app", "dev", "test", "stage", "prod", "admin",
        "login", "auth", "secure", "payment", "billing", "download", "update",
        "support", "help", "docs", "news", "smtp", "imap", "ns1", "ns2",
        "dns", "vpn", "remote", "portal", "cloud", "server", "microsoft",
        "windows", "office", "google", "apple", "amazon", "account"
    ];

    public static double ShannonEntropy(string text)
    {
        if (string.IsNullOrEmpty(text)) return 0.0;
        var counts = new Dictionary<char, int>();
        foreach (var ch in text.ToLowerInvariant())
        {
            counts[ch] = counts.GetValueOrDefault(ch, 0) + 1;
        }

        double len = text.Length;
        var entropy = 0.0;
        foreach (var count in counts.Values)
        {
            var p = count / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    public static double ConsonantRatio(string text)
    {
        var alpha = text.ToLowerInvariant().Where(char.IsAsciiLetter).ToArray();
        if (alpha.Length == 0) return 0.0;
        var consonants = alpha.Count(c => !"aeiou".Contains(c));
        return (double)consonants / alpha.Length;
    }

    public static double DigitRatio(string text)
    {
        if (string.IsNullOrEmpty(text)) return 0.0;
        var digits = text.Count(char.IsAsciiDigit);
        return (double)digits / text.Length;
    }

    public static double BigramScore(string text)
    {
        if (text.Length < 2) return 1.0;
        var totalBigrams = text.Length - 1;
        var matching = 0;
        var lower = text.ToLowerInvariant();
        for (var i = 0; i < totalBigrams; i++)
        {
            var bg = lower.Substring(i, 2);
            if (CommonBigrams.Contains(bg)) matching++;
        }

        return (double)matching / totalBigrams;
    }

    public static DgaScoreResult ScoreDomain(string domain)
    {
        domain = (domain ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        var parts = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length < 2)
        {
            return new DgaScoreResult(domain, 0, 0, 0, 0, 1.0, false, 0.0, ["not a valid domain"]);
        }

        if (KnownGoodSuffixes.Any(suffix => domain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
        {
            return new DgaScoreResult(domain, 0, 0, 0, 0, 1.0, false, 0.0, ["known-good suffix"]);
        }

        var labels = string.Join('.', parts[..^1]);
        var tld = parts[^1];
        var sldClean = Regex.Replace(labels, @"[^a-z0-9]", "");

        var entropy = ShannonEntropy(sldClean);
        var cRatio = ConsonantRatio(sldClean);
        var dRatio = DigitRatio(sldClean);
        var bScore = BigramScore(sldClean);
        var length = sldClean.Length;

        var factors = new List<string>();
        var score = 0;

        if (RiskyTlds.Contains(tld))
        {
            score += 15;
            factors.Add($"risky TLD .{tld}");
        }

        if (entropy >= 3.8)
        {
            score += 30;
            factors.Add($"high entropy ({entropy:F2})");
        }
        else if (entropy >= 3.3)
        {
            score += 15;
            factors.Add($"elevated entropy ({entropy:F2})");
        }

        if (length >= 25)
        {
            score += 15;
            factors.Add($"long label ({length} chars)");
        }
        else if (length >= 18)
        {
            score += 8;
            factors.Add($"medium-long label ({length} chars)");
        }

        if (dRatio >= 0.4)
        {
            score += 20;
            factors.Add($"digit-heavy ({dRatio:P0})");
        }
        else if (dRatio >= 0.25)
        {
            score += 10;
            factors.Add($"elevated digits ({dRatio:P0})");
        }

        if (cRatio >= 0.75)
        {
            score += 15;
            factors.Add($"consonant-heavy ({cRatio:P0})");
        }

        if (bScore < 0.10 && length >= 8)
        {
            score += 15;
            factors.Add($"low English bigram score ({bScore:P0})");
        }

        var hyphens = labels.Count(c => c == '-');
        if (hyphens >= 4)
        {
            score += 10;
            factors.Add($"{hyphens} hyphens");
        }

        var foundWords = CommonWords.Where(w => labels.Contains(w)).Take(2).ToArray();
        if (foundWords.Length > 0)
        {
            score = Math.Max(0, score - 25);
            factors.Add($"dictionary words: {string.Join(',', foundWords)}");
        }

        var boundedScore = Math.Clamp(score, 0, 100);
        var isDga = boundedScore >= AlertThreshold;
        var confidence = Math.Clamp(boundedScore / 100.0, 0.0, 1.0);

        if (factors.Count == 0)
        {
            factors.Add("benign characteristics");
        }

        return new DgaScoreResult(
            domain,
            boundedScore,
            entropy,
            cRatio,
            dRatio,
            bScore,
            isDga,
            confidence,
            factors);
    }
}
