using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>How a feed's bytes are parsed. Each format has its own strict parser in <see cref="ThreatFeedParser"/>.</summary>
public enum ThreatFeedFormat
{
    /// <summary>One IP, CIDR, domain or hash per line; '#' and ';' comment lines; anything after whitespace is ignored.</summary>
    Lines,
    /// <summary>hosts-file lines ("127.0.0.1 domain").</summary>
    HostsFile,
    /// <summary>One URL per line; the host is indexed.</summary>
    UrlLines,
    FeodoCsv,
    SpamhausJsonLines,
    ThreatFoxJson,
    LolDriversJson,
    LolbasJson,
    /// <summary>Gzip IPtoASN table (start, end, ASN, country, network name).</summary>
    Ip2AsnGzip,
}

/// <summary>
/// One allow-listed public database. URLs are fixed HTTPS endpoints chosen from each project's own documentation;
/// redirects are refused, so a moved feed shows as failed instead of silently following somewhere else.
/// </summary>
public sealed record ThreatFeedDefinition(
    string Id,
    string Name,
    string Provider,
    string Kind,
    ThreatFeedFormat Format,
    string Url,
    int MaximumBytes,
    TimeSpan RefreshInterval,
    string Severity,
    string Technique,
    string DefaultLabel,
    string Purpose,
    string License,
    string Homepage)
{
    public string Host => new Uri(Url).Host;
}

public static class ThreatFeedCatalog
{
    private const int MiB = 1024 * 1024;

    public static readonly IReadOnlyList<ThreatFeedDefinition> All =
    [
        new("loldrivers", "LOLDrivers", "MagicSword / LOLDrivers project", ThreatFeedKinds.Driver, ThreatFeedFormat.LolDriversJson,
            "https://www.loldrivers.io/api/drivers.json", 96 * MiB, TimeSpan.FromHours(24), "HIGH", "T1068", "Known vulnerable or malicious driver",
            "Drivers attackers load to switch off security software (bring-your-own-vulnerable-driver).", "Apache-2.0", "https://www.loldrivers.io/"),
        new("lolbas", "LOLBAS", "LOLBAS Project", ThreatFeedKinds.Lolbin, ThreatFeedFormat.LolbasJson,
            "https://lolbas-project.github.io/api/lolbas.json", 8 * MiB, TimeSpan.FromDays(3), "LOW", "T1218", "Living-off-the-land binary",
            "Built-in Windows programs that attackers misuse to download or run code. Shown as context, never as a verdict.", "GPL-3.0", "https://lolbas-project.github.io/"),
        new("threatfox", "ThreatFox (recent)", "abuse.ch", ThreatFeedKinds.Mixed, ThreatFeedFormat.ThreatFoxJson,
            "https://threatfox.abuse.ch/export/json/recent/", 48 * MiB, TimeSpan.FromHours(6), "HIGH", "T1071", "Malware indicator",
            "Malware command servers, payload sites and sample hashes shared by researchers in the last 48 hours.", "CC0-1.0", "https://threatfox.abuse.ch/"),
        new("feodo", "Feodo Tracker botnet C2", "abuse.ch", ThreatFeedKinds.Ip, ThreatFeedFormat.FeodoCsv,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", 4 * MiB, TimeSpan.FromHours(6), "HIGH", "T1071", "Botnet command server",
            "Command servers for banking and loader botnets (Emotet, QakBot, Dridex and others).", "CC0-1.0", "https://feodotracker.abuse.ch/"),
        new("urlhaus", "URLhaus malware hosts", "abuse.ch", ThreatFeedKinds.Domain, ThreatFeedFormat.HostsFile,
            "https://urlhaus.abuse.ch/downloads/hostfile/", 16 * MiB, TimeSpan.FromHours(6), "MEDIUM", "T1189", "Malware distribution site",
            "Websites currently serving malware downloads.", "CC0-1.0", "https://urlhaus.abuse.ch/"),
        new("malwarebazaar", "MalwareBazaar (recent)", "abuse.ch", ThreatFeedKinds.Hash, ThreatFeedFormat.Lines,
            "https://bazaar.abuse.ch/export/txt/sha256/recent/", 16 * MiB, TimeSpan.FromHours(6), "CRITICAL", "T1204", "Known malware sample",
            "SHA-256 fingerprints of malware samples submitted in the last 48 hours.", "CC0-1.0", "https://bazaar.abuse.ch/"),
        new("spamhaus-drop", "Spamhaus DROP (IPv4)", "The Spamhaus Project", ThreatFeedKinds.Ip, ThreatFeedFormat.SpamhausJsonLines,
            "https://www.spamhaus.org/drop/drop_v4.json", 8 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1071", "Hijacked or criminal network",
            "Address ranges controlled by spammers and cyber-criminals (\"Don't Route Or Peer\").", "Spamhaus DROP terms (free use)", "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"),
        new("spamhaus-drop-v6", "Spamhaus DROP (IPv6)", "The Spamhaus Project", ThreatFeedKinds.Ip, ThreatFeedFormat.SpamhausJsonLines,
            "https://www.spamhaus.org/drop/drop_v6.json", 4 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1071", "Hijacked or criminal network",
            "IPv6 ranges controlled by spammers and cyber-criminals.", "Spamhaus DROP terms (free use)", "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"),
        new("et-compromised", "Emerging Threats compromised hosts", "Proofpoint Emerging Threats", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 8 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1071", "Known compromised host",
            "Machines observed attacking others because they were compromised.", "ET Open (BSD)", "https://rules.emergingthreats.net/"),
        new("firehol-level1", "FireHOL level 1", "FireHOL", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", 8 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1071", "High-confidence attacker network",
            "A low-false-positive blend of DShield, Feodo and Spamhaus lists. Private and reserved ranges are skipped.", "Per source (aggregated)", "https://iplists.firehol.org/"),
        new("ipsum", "IPsum (3+ lists)", "Miroslav Stampar", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", 8 * MiB, TimeSpan.FromHours(24), "LOW", "T1071", "Address on 3 or more blocklists",
            "Addresses that at least three independent blocklists agree on.", "Unlicense", "https://github.com/stamparm/ipsum"),
        new("cins", "CINS Army", "Collective Intelligence Network Security", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://cinsscore.com/list/ci-badguys.txt", 8 * MiB, TimeSpan.FromHours(24), "LOW", "T1071", "Poor-reputation address",
            "Addresses with consistently bad behaviour seen by Sentinel IPS sensors.", "Free use", "https://cinsscore.com/"),
        new("greensnow", "GreenSnow", "GreenSnow", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://blocklist.greensnow.co/greensnow.txt", 8 * MiB, TimeSpan.FromHours(24), "LOW", "T1110", "Brute-force or scanning source",
            "Addresses caught brute-forcing or scanning.", "Free use", "https://greensnow.co/"),
        new("blocklist-de", "blocklist.de", "blocklist.de", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://lists.blocklist.de/lists/all.txt", 16 * MiB, TimeSpan.FromHours(24), "LOW", "T1110", "Recent attack source",
            "Addresses reported for attacks on mail, SSH, web and other services in the last 48 hours.", "Free use", "https://www.blocklist.de/"),
        new("tor-exit", "Tor exit relays", "The Tor Project", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://check.torproject.org/torbulkexitlist", 4 * MiB, TimeSpan.FromHours(6), "LOW", "T1090.003", "Tor exit relay",
            "Exit relays of the Tor network. Tor is legitimate, but malware also uses it to hide where it connects.", "Public", "https://www.torproject.org/"),
        new("phishing-army", "Phishing Army", "Andrea Draghetti", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://phishing.army/download/phishing_army_blocklist.txt", 32 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1566", "Phishing site",
            "Phishing domains collected from PhishTank, OpenPhish, CERT Polska and others.", "CC BY-NC 4.0 (personal use)", "https://phishing.army/"),
        new("openphish", "OpenPhish community", "OpenPhish", ThreatFeedKinds.Domain, ThreatFeedFormat.UrlLines,
            "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", 4 * MiB, TimeSpan.FromHours(12), "MEDIUM", "T1566", "Phishing site",
            "Live phishing pages; the site name is indexed.", "Non-commercial use (OpenPhish terms)", "https://openphish.com/"),
        new("stalkerware", "Stalkerware indicators", "Echap / Stalkerware Indicators", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts", 4 * MiB, TimeSpan.FromHours(24), "HIGH", "T1430", "Stalkerware server",
            "Servers used by commercial stalkerware and spy apps. A lookup from this PC can mean something on your network reports to one.", "CC BY 4.0", "https://github.com/AssoEchap/stalkerware-indicators"),
        new("ip-origin", "IP origin (country and network)", "IPtoASN", ThreatFeedKinds.Geo, ThreatFeedFormat.Ip2AsnGzip,
            "https://iptoasn.com/data/ip2asn-combined.tsv.gz", 48 * MiB, TimeSpan.FromDays(7), "LOW", "", "",
            "Offline map of every routed address block to its country and network owner, so you can see roughly where connections come from without asking anyone.", "Public domain (PDDL)", "https://iptoasn.com/"),
    ];

    public static ThreatFeedDefinition? Find(string id) => All.FirstOrDefault(feed => feed.Id == id);
}
