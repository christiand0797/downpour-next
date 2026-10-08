using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Everything known about one local observation that one or more databases list.</summary>
public sealed record ThreatEvidence(
    string Place,
    string Indicator,
    IReadOnlyList<(ThreatFeedDefinition Feed, string Label)> Hits,
    string? Program = null,
    string? ProgramPath = null,
    bool? Signed = null,
    string? Signer = null,
    int? RemotePort = null,
    bool? ConnectionObserved = null,
    string? ConnectedProgram = null,
    bool ParentDomainOnly = false,
    string? Network = null,
    bool Sinkholed = false);

public sealed record ThreatAssessment(string Verdict, int Confidence, string Severity, IReadOnlyList<string> Reasons);

public static class ThreatVerdicts
{
    public const string Confirmed = "confirmed";
    public const string Likely = "likely";
    public const string Review = "needs-review";
    public const string LikelyBenign = "likely-benign";
    public const string VulnerableLegitimate = "vulnerable-legitimate";
    public const string Blocked = "blocked";

    /// <summary>Verdicts that mean "not a threat"; their alerts are retired automatically.</summary>
    public static bool IsCleared(string verdict) => verdict is Blocked;

    public static string Label(string verdict) => verdict switch
    {
        Confirmed => "Confirmed threat",
        Likely => "Likely threat",
        Review => "Needs review",
        VulnerableLegitimate => "Legitimate but vulnerable",
        Blocked => "Already blocked by this PC",
        _ => "Likely benign",
    };
}

/// <summary>
/// Corroborates database matches before anything is called a threat. A single weak signal (one reputation list, a DNS name
/// that was only looked up) is never presented as a confirmed threat; independent agreement, exact file hashes, an
/// observed connection, unsigned code in user-writable folders and malware-specific feeds raise confidence. The result
/// always carries the reasons so a person or a third-party reviewer can check the reasoning. Nothing here acts on the PC.
/// </summary>
public static class ThreatVerdictEngine
{
    private static readonly HashSet<string> MalwareFeeds = new(StringComparer.Ordinal)
    {
        "threatfox", "feodo", "malwarebazaar", "urlhaus", "c2intel-ips", "c2intel-domains", "threatview-cobaltstrike", "sigbase-c2",
        "sigbase-hashes", "mandiant-redteam", "blp-ransomware", "shadowwhisperer-malware", "firehol-webclient",
    };
    private static readonly HashSet<string> ReputationFeeds = new(StringComparer.Ordinal)
    {
        "spamhaus-drop", "spamhaus-drop-v6", "et-compromised", "firehol-level1", "ipsum", "cins", "greensnow", "blocklist-de",
        "et-block", "firehol-level2", "firehol-level3", "firehol-abusers", "dshield", "bruteforceblocker", "ipsum-5",
    };
    private static readonly HashSet<string> PhishingFeeds = new(StringComparer.Ordinal)
        { "phishing-army", "openphish", "hagezi-tif", "cert-pl", "blp-scam", "scamblocklist", "spam404", "nocoin", "blp-crypto" };
    /// <summary>Mercenary-spyware and stalkerware infrastructure: specific to spying, so weighted like stalkerware.</summary>
    private static readonly HashSet<string> SpywareFeeds = new(StringComparer.Ordinal) { "stalkerware", "amnesty-pegasus", "amnesty-predator" };
    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
        { "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe", "arc.exe" };
    private static readonly HashSet<int> WebPorts = [80, 443, 8080, 8443];

    public static ThreatAssessment Assess(ThreatEvidence e)
    {
        var reasons = new List<string>();
        var feeds = e.Hits.Select(h => h.Feed).DistinctBy(f => f.Id).ToArray();
        var names = string.Join(", ", feeds.Select(f => f.Name));
        reasons.Add(feeds.Length == 1 ? $"Listed by 1 database: {names}." : $"Listed by {feeds.Length} independent databases: {names}.");

        if (e.Place is ThreatMatchPlaces.Driver) return Driver(e, feeds, reasons);
        if (e.Sinkholed)
        {
            reasons.Add("Every address this name resolves to is 0.0.0.0 or a loopback address: this PC's hosts file or DNS filter already blocks it, so it was not visited. This is protection working, not a threat.");
            return new(ThreatVerdicts.Blocked, 2, "LOW", reasons);
        }
        if (e.Place is ThreatMatchPlaces.Program) return Program(e, feeds, reasons);

        int score;
        if (feeds.Any(f => SpywareFeeds.Contains(f.Id))) { score = 60; reasons.Add("Stalkerware and mercenary-spyware server lists are specific to spying tools."); }
        else if (feeds.Any(f => MalwareFeeds.Contains(f.Id))) { score = feeds.Any(f => f.Id == "feodo") ? 70 : 55; reasons.Add("A malware-specific database lists it (stronger than a general reputation list)."); }
        else if (feeds.Any(f => PhishingFeeds.Contains(f.Id))) { score = 35; reasons.Add("Phishing lists are broad and also catch ad and gambling domains."); }
        else if (feeds.Any(f => ReputationFeeds.Contains(f.Id))) { score = 30; reasons.Add("Reputation lists record attacking or scanning addresses, which are often shared or recycled."); }
        else { score = 15; reasons.Add("Only an informational list matches (for example a Tor exit relay)."); }

        var independent = feeds.Count(f => f.Kind != ThreatFeedKinds.Lolbin && f.Id != "tor-exit");
        if (independent > 1)
        {
            var bonus = Math.Min(30, (independent - 1) * 12);
            score += bonus;
            reasons.Add($"{independent} independent databases agree (+{bonus}).");
        }
        if (e.ParentDomainOnly) { score -= 10; reasons.Add("Only a parent domain is listed, not this exact name (-10)."); }

        if (e.Place == ThreatMatchPlaces.Dns)
        {
            if (e.ConnectionObserved == true)
            {
                score += 25;
                reasons.Add($"{e.ConnectedProgram ?? "A program"} is connected to an address this name resolved to (+25).");
            }
            else
            {
                score -= 10;
                reasons.Add("Only the name lookup was seen; no connection to it was observed (often an ad, link preview or blocked request) (-10).");
            }
        }

        if (e.Place == ThreatMatchPlaces.Connection)
        {
            if (e.Program is { } program && Browsers.Contains(program))
            {
                score -= 10;
                reasons.Add($"{program} is a web browser, so this is most likely a visited site or ad rather than malware on the PC (-10).");
            }
            else if (e.Program is { } other)
            {
                score += 10;
                reasons.Add($"{other} (not a browser) made the connection (+10).");
            }
            if (e.RemotePort is { } port && !WebPorts.Contains(port) && feeds.Any(f => MalwareFeeds.Contains(f.Id)))
            {
                score += 10;
                reasons.Add($"Uses non-web port {port}, typical of command-and-control (+10).");
            }
            if (IsUserWritable(e.ProgramPath))
            {
                score += 10;
                reasons.Add("The program runs from a user-writable folder (+10).");
            }
        }
        if (e.Network is { Length: > 0 } network) reasons.Add($"Network owner: {network}.");
        return Finish(score, feeds, reasons);
    }

    private static ThreatAssessment Driver(ThreatEvidence e, ThreatFeedDefinition[] feeds, List<string> reasons)
    {
        var malicious = e.Hits.Any(h => h.Label.StartsWith("Malicious", StringComparison.Ordinal));
        reasons.Add("Exact file-hash match on the loaded driver.");
        if (malicious)
        {
            reasons.Add("LOLDrivers classifies this driver as malicious.");
            return new(ThreatVerdicts.Confirmed, 95, "CRITICAL", reasons);
        }
        if (e.Signed == true)
        {
            reasons.Add($"Validly signed{(e.Signer is { Length: > 0 } signer ? $" by {signer}" : "")}: a genuine vendor driver with a known flaw, not malware. Risk: attackers can load it to switch off security software. Update or uninstall the software that installed it.");
            return new(ThreatVerdicts.VulnerableLegitimate, 60, "MEDIUM", reasons);
        }
        reasons.Add(e.Signed == false ? "The driver file is not validly signed." : "The signature could not be checked.");
        return new(ThreatVerdicts.Likely, 80, "HIGH", reasons);
    }

    private static ThreatAssessment Program(ThreatEvidence e, ThreatFeedDefinition[] feeds, List<string> reasons)
    {
        reasons.Add("Exact SHA-256/SHA-1/MD5 match on the running program's file.");
        var score = 90;
        if (feeds.Length > 1) { score = 97; reasons.Add("More than one malware database has this exact file."); }
        if (e.Signed == true)
        {
            score -= 15;
            reasons.Add($"The file is validly signed{(e.Signer is { Length: > 0 } signer ? $" by {signer}" : "")}; signed malware exists, but double-check before acting (-15).");
        }
        if (IsUserWritable(e.ProgramPath)) reasons.Add("It runs from a user-writable folder.");
        return Finish(score, feeds, reasons, critical: true);
    }

    private static ThreatAssessment Finish(int score, ThreatFeedDefinition[] feeds, List<string> reasons, bool critical = false)
    {
        score = Math.Clamp(score, 1, 99);
        var verdict = score >= 85 ? ThreatVerdicts.Confirmed : score >= 60 ? ThreatVerdicts.Likely : score >= 30 ? ThreatVerdicts.Review : ThreatVerdicts.LikelyBenign;
        var strongest = feeds.Select(f => f.Severity).OrderByDescending(Rank).FirstOrDefault() ?? "LOW";
        var severity = verdict switch
        {
            ThreatVerdicts.Confirmed => critical ? "CRITICAL" : Max(strongest, "HIGH"),
            ThreatVerdicts.Likely => strongest,
            ThreatVerdicts.Review => Rank(strongest) > Rank("MEDIUM") ? "MEDIUM" : "LOW",
            _ => "LOW",
        };
        if (verdict == ThreatVerdicts.LikelyBenign) reasons.Add("Not enough independent evidence to treat this as a threat; kept for the record only.");
        return new(verdict, score, severity, reasons);
    }

    private static bool IsUserWritable(string? path) =>
        path is { Length: > 0 } p && (p.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) || p.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                      p.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) || p.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase));

    private static int Rank(string severity) => severity switch { "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, _ => 1 };
    private static string Max(string a, string b) => Rank(a) >= Rank(b) ? a : b;
}
