using System.Text.RegularExpressions;

namespace Downpour.Core;

public sealed record PhishingAnalysisResult(
    int Score,
    string Verdict,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> MatchedCategories,
    int UrgencyHits,
    int AuthorityHits,
    int FearHits,
    int GrammarHits,
    int BlobHits,
    int RedirectHits,
    bool QrHits);

/// <summary>
/// Fully local, context-aware NLP phishing and social engineering text analyzer.
/// Ported from v29 AegisNLPPhishingEngine.
/// Evaluates urgency triggers, authority impersonation, fear/reward cues, grammar indicators,
/// ephemeral/blob URIs, redirect shorteners, and multi-stage QR instructions.
/// Strictly local text processing with no remote network calls.
/// </summary>
public static class AegisPhishingAnalyzer
{
    public const int PhishingThreshold = 70;
    public const int SuspiciousThreshold = 50;

    // 1. Urgency & pressure language patterns (+15 each, max 30)
    private static readonly Regex[] UrgencyPatterns =
    [
        new(@"\b(urgent|immediately|right now|act now|expires? (today|now|in \d+)|limited time|last chance)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(within \d+ (hours?|minutes?|days?))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(deadline|overdue|past due|final notice|last warning|account (suspended|terminated|banned))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(verify (now|immediately|your account|your information))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(click (here|now|this link) (to|or))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    // 2. Authority impersonation patterns (+20 each, max 25)
    private static readonly Regex[] AuthorityPatterns =
    [
        new(@"\b(microsoft|apple|google|amazon|paypal|netflix|irs|fbi|dhs|cisa|interpol)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(your (bank|financial institution|credit card company|it department|help\s*desk))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(tech(nical)? support|system administrator|account (team|department|security))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(official (notice|communication|security alert|warning from))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    // 3. Reward/fear triggers (+20 each, max 25)
    private static readonly Regex[] RewardFearPatterns =
    [
        new(@"\b(you (have|won|are selected|are the winner|qualify))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b((\$|EUR|GBP|USD)\d+[\d,]* (prize|gift card|reward|refund|payment))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(your (password|account|data|information) (has been|was) (compromised|breached|leaked|stolen|hacked))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(suspicious (activity|login|sign-in|access) (detected|found) on your account)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(confirm (your identity|your account|who you are|ownership))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(unauthorized (access|transaction|login|activity) (was|has been) (detected|attempted))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(your (session|access|login) (will|has) expire[sd]?)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(failure to (respond|verify|confirm|act) (will|may) result in)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    // 4. Grammar/tone mismatch indicators (+10 each, max 15)
    private static readonly Regex[] GrammarIndicators =
    [
        new(@"\b(kindly (do|provide|send|click|confirm|update))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(dear (valued|esteemed|beloved|respected) (customer|client|user|sir|madam))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(revert (back|to me|this email))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(below mentioned|aforementioned document|attached herewith)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(do the needful|revert (back|asap)|your good self)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(we are contacting you (regarding|about|in reference))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    // 5. Blob/ephemeral URI patterns (+30)
    private static readonly Regex[] BlobUriPatterns =
    [
        new(@"blob:https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"blob:http://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"data:text/html;base64,", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"data:application/x-www-form-urlencoded", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"javascript:(?!void)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    // 6. Suspicious redirect indicators / URL shorteners (+15)
    private static readonly Regex[] RedirectIndicators =
    [
        new(@"https?://[a-z0-9]{10,}\.(?:tk|ml|ga|cf|gq|xyz|click|link|ly|gl)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"https?://[a-z0-9]{30,}\.", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(t\.co/|bit\.ly/|tinyurl\.com/|goo\.gl/|ow\.ly/)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(is\.gd/|v\.gd/|shorturl\.at/|cutt\.ly/)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(rb\.gy/|tiny\.cc/|qr\.ae/)", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    // 7. Multi-stage QR code patterns (+20)
    private static readonly Regex QrPattern = new(
        @"(scan|photograph|point your (?:camera|phone))\s+(?:at\s+)?(?:(?:the|this)\s+)?(?:below\s+)?qr\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Analyzes the input text for phishing, credential harvesting, and social engineering patterns.
    /// </summary>
    public static PhishingAnalysisResult Analyze(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return new PhishingAnalysisResult(0, "CLEAN", ["No text content provided"], [], 0, 0, 0, 0, 0, 0, false);
        }

        var score = 0;
        var reasons = new List<string>();
        var categories = new List<string>();

        // 1. Urgency triggers (+15 each, max 30)
        var urgencyHits = UrgencyPatterns.Count(p => p.IsMatch(text));
        if (urgencyHits > 0)
        {
            var pts = Math.Min(urgencyHits * 15, 30);
            score += pts;
            reasons.Add($"Urgency language ({urgencyHits} triggers) +{pts}");
            categories.Add("Urgency");
        }

        // 2. Authority impersonation (+20 each, max 25)
        var authHits = AuthorityPatterns.Count(p => p.IsMatch(text));
        if (authHits > 0)
        {
            var pts = Math.Min(authHits * 20, 25);
            score += pts;
            reasons.Add($"Authority impersonation ({authHits} patterns) +{pts}");
            categories.Add("Authority");
        }

        // 3. Reward / fear triggers (+20 each, max 25)
        var fearHits = RewardFearPatterns.Count(p => p.IsMatch(text));
        if (fearHits > 0)
        {
            var pts = Math.Min(fearHits * 20, 25);
            score += pts;
            reasons.Add($"Fear/reward trigger ({fearHits} cues) +{pts}");
            categories.Add("Psychological Trigger");
        }

        // 4. Grammar / tone mismatch (+10 each, max 15)
        var grammarHits = GrammarIndicators.Count(p => p.IsMatch(text));
        if (grammarHits > 0)
        {
            var pts = Math.Min(grammarHits * 10, 15);
            score += pts;
            reasons.Add($"Grammar/tone mismatch ({grammarHits} phrases) +{pts}");
            categories.Add("Tone Mismatch");
        }

        // 5. Blob / Ephemeral URI (+30)
        var blobHits = BlobUriPatterns.Count(p => p.IsMatch(text));
        if (blobHits > 0)
        {
            score += 30;
            reasons.Add("Blob/ephemeral URI detected (+30) — memory-only link evasion");
            categories.Add("Link Evasion");
        }

        // 6. Suspicious redirect / shortener (+15)
        var redirectHits = RedirectIndicators.Count(p => p.IsMatch(text));
        if (redirectHits > 0)
        {
            score += 15;
            reasons.Add("Redirect chain / URL shortener (+15)");
            categories.Add("Redirect Chain");
        }

        // 7. Multi-stage QR code instruction (+20)
        var qrHits = QrPattern.IsMatch(text);
        if (qrHits)
        {
            score += 20;
            reasons.Add("Multi-stage QR code instruction (+20)");
            categories.Add("QR Evasion");
        }

        var finalScore = Math.Clamp(score, 0, 100);
        string verdict;
        if (finalScore >= PhishingThreshold)
        {
            verdict = "PHISHING";
        }
        else if (finalScore >= SuspiciousThreshold)
        {
            verdict = "SUSPICIOUS";
        }
        else
        {
            verdict = "CLEAN";
            if (reasons.Count == 0)
            {
                reasons.Add("No suspicious urgency, impersonation, or deceptive indicators detected.");
            }
        }

        return new PhishingAnalysisResult(
            finalScore,
            verdict,
            reasons,
            categories,
            urgencyHits,
            authHits,
            fearHits,
            grammarHits,
            blobHits,
            redirectHits,
            qrHits);
    }
}
