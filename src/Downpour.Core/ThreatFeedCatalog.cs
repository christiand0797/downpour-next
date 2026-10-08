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
    /// <summary>
    /// Separated values (CSV, "value;description"): the indicator is field <see cref="ThreatFeedDefinition.Column"/>, the
    /// label optionally field <see cref="ThreatFeedDefinition.LabelColumn"/>. A header line simply fails validation once.
    /// </summary>
    Delimited,
    /// <summary>LOLRMM: remote monitoring/management and remote-access tools (program names as context, service domains).</summary>
    LolRmmJson,
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
    string Homepage,
    char Separator = ',',
    int Column = 0,
    int LabelColumn = -1)
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
        // Command-and-control and red-team tooling.
        new("c2intel-ips", "C2IntelFeeds C2 servers", "drb-ra / C2IntelFeeds", ThreatFeedKinds.Ip, ThreatFeedFormat.Delimited,
            "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv", 4 * MiB, TimeSpan.FromHours(12), "HIGH", "T1071", "Attack framework command server",
            "Servers running Cobalt Strike and other attack frameworks, found by internet scanning in the last 30 days.", "Free use", "https://github.com/drb-ra/C2IntelFeeds", LabelColumn: 1),
        new("c2intel-domains", "C2IntelFeeds C2 domains", "drb-ra / C2IntelFeeds", ThreatFeedKinds.Domain, ThreatFeedFormat.Delimited,
            "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv", 4 * MiB, TimeSpan.FromHours(12), "HIGH", "T1071", "Attack framework command domain",
            "Domain names pointing at attack-framework command servers (last 30 days, abused shared services filtered out).", "Free use", "https://github.com/drb-ra/C2IntelFeeds", LabelColumn: 1),
        new("threatview-cobaltstrike", "Threatview Cobalt Strike C2", "Threatview.io", ThreatFeedKinds.Ip, ThreatFeedFormat.Delimited,
            "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt", 8 * MiB, TimeSpan.FromHours(24), "HIGH", "T1071", "Cobalt Strike command server",
            "High-confidence Cobalt Strike team servers, the attack tool most used by ransomware gangs.", "Free use (Threatview terms)", "https://threatview.io/"),
        new("sigbase-c2", "Signature-Base C2 indicators", "Florian Roth / Nextron signature-base", ThreatFeedKinds.Mixed, ThreatFeedFormat.Delimited,
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt", 4 * MiB, TimeSpan.FromDays(3), "HIGH", "T1071", "Known APT or malware C2",
            "Command servers from published APT and malware investigations, curated for the THOR and LOKI scanners.", "Detection Rule License 1.1", "https://github.com/Neo23x0/signature-base", Separator: ';', LabelColumn: 1),
        // Malware file fingerprints.
        new("sigbase-hashes", "Signature-Base malware hashes", "Florian Roth / Nextron signature-base", ThreatFeedKinds.Hash, ThreatFeedFormat.Delimited,
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt", 8 * MiB, TimeSpan.FromDays(3), "CRITICAL", "T1204", "Known APT or malware file",
            "Fingerprints of malware and hacking tools from published investigations, each named after its campaign.", "Detection Rule License 1.1", "https://github.com/Neo23x0/signature-base", Separator: ';', LabelColumn: 1),
        new("mandiant-redteam", "Mandiant stolen red-team tools", "Mandiant (FireEye)", ThreatFeedKinds.Hash, ThreatFeedFormat.Delimited,
            "https://raw.githubusercontent.com/mandiant/red_team_tool_countermeasures/master/all-hashes.csv", 2 * MiB, TimeSpan.FromDays(7), "CRITICAL", "T1588.002", "FireEye red-team tool (stolen 2020)",
            "Hacking tools stolen from FireEye in 2020 and released so defenders could detect them.", "BSD-2-Clause", "https://github.com/mandiant/red_team_tool_countermeasures", Column: 2),
        // Spyware infrastructure.
        new("amnesty-pegasus", "NSO Pegasus spyware domains", "Amnesty International Security Lab", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/domains.txt", 2 * MiB, TimeSpan.FromDays(7), "HIGH", "T1430", "NSO Pegasus spyware server",
            "Servers of NSO Group's Pegasus spyware, used against journalists and activists, from the Pegasus Project investigation.", "CC BY 4.0", "https://github.com/AmnestyTech/investigations"),
        new("amnesty-predator", "Cytrox Predator spyware domains", "Amnesty International Security Lab", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-12-16_cytrox/domains.txt", 2 * MiB, TimeSpan.FromDays(7), "HIGH", "T1430", "Cytrox Predator spyware server",
            "Servers of Cytrox's Predator mercenary spyware, from Amnesty International's investigation.", "CC BY 4.0", "https://github.com/AmnestyTech/investigations"),
        // Malware, ransomware, scam and phishing domains.
        new("hagezi-tif", "HaGeZi Threat Intelligence (mini)", "HaGeZi DNS blocklists", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", 16 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1071", "Malware, phishing or scam domain",
            "The most active malware, phishing, scam and command-server domains merged from dozens of threat feeds.", "GPL-3.0", "https://github.com/hagezi/dns-blocklists"),
        new("cert-pl", "CERT Polska warning list", "CERT Polska", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://hole.cert.pl/domains/v2/domains.txt", 16 * MiB, TimeSpan.FromHours(12), "MEDIUM", "T1566", "Phishing or fraud site (CERT Polska)",
            "Phishing and fraud domains confirmed by Poland's national computer emergency team.", "Free use (CERT Polska)", "https://cert.pl/en/warning-list/"),
        new("shadowwhisperer-malware", "ShadowWhisperer malware", "ShadowWhisperer", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware", 8 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1189", "Malware site",
            "Domains spreading malware, hand-curated.", "MIT", "https://github.com/ShadowWhisperer/BlockLists"),
        new("blp-ransomware", "Block List Project ransomware", "The Block List Project", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt", 4 * MiB, TimeSpan.FromHours(24), "HIGH", "T1486", "Ransomware domain",
            "Domains used by ransomware for payment, delivery or command.", "Unlicense", "https://blocklistproject.github.io/Lists/"),
        new("blp-scam", "Block List Project scams", "The Block List Project", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt", 4 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1566", "Scam site",
            "Fake shops, tech-support scams and other fraud sites.", "Unlicense", "https://blocklistproject.github.io/Lists/"),
        new("scamblocklist", "Scam Blocklist", "durablenapkin", ThreatFeedKinds.Domain, ThreatFeedFormat.HostsFile,
            "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt", 4 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1566", "Scam site",
            "Fake stores, investment and impersonation scams.", "MIT", "https://github.com/durablenapkin/scamblocklist"),
        new("spam404", "Spam404 scams", "Spam404", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt", 4 * MiB, TimeSpan.FromDays(3), "MEDIUM", "T1566", "Scam or fake-download site",
            "Scam, fake-download and survey-fraud sites.", "CC BY-SA 4.0", "https://www.spam404.com/"),
        // Cryptojacking.
        new("nocoin", "NoCoin cryptominers", "hoshsadiq / NoCoin", ThreatFeedKinds.Domain, ThreatFeedFormat.HostsFile,
            "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", 2 * MiB, TimeSpan.FromDays(3), "MEDIUM", "T1496", "Cryptocurrency miner",
            "Browser and malware cryptocurrency-mining services that use your processor without asking.", "MIT", "https://github.com/hoshsadiq/adblock-nocoin-list"),
        new("blp-crypto", "Block List Project cryptojacking", "The Block List Project", ThreatFeedKinds.Domain, ThreatFeedFormat.Lines,
            "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt", 2 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1496", "Cryptojacking domain",
            "Cryptojacking and mining-pool domains.", "Unlicense", "https://blocklistproject.github.io/Lists/"),
        // Attacking and abusive addresses.
        new("et-block", "Emerging Threats block list", "Proofpoint Emerging Threats", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", 4 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1071", "Emerging Threats blocked network",
            "Networks Emerging Threats recommends blocking (DShield top attackers, Spamhaus and abuse.ch command servers).", "ET Open (BSD)", "https://rules.emergingthreats.net/"),
        new("firehol-level2", "FireHOL level 2", "FireHOL", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset", 8 * MiB, TimeSpan.FromHours(24), "LOW", "T1071", "Recent attacker (48 hours)",
            "Addresses that attacked others in the last 48 hours, from several attack-tracking lists.", "Per source (aggregated)", "https://iplists.firehol.org/"),
        new("firehol-level3", "FireHOL level 3", "FireHOL", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset", 8 * MiB, TimeSpan.FromHours(24), "LOW", "T1071", "Attacker or malware host (30 days)",
            "Attackers, spyware and malware hosts seen in the last 30 days.", "Per source (aggregated)", "https://iplists.firehol.org/"),
        new("firehol-webclient", "FireHOL web-client threats", "FireHOL", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset", 2 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1189", "Dangerous for web browsing",
            "Addresses a web browser or app should never connect to: malware hosts, command servers and exploit kits.", "Per source (aggregated)", "https://iplists.firehol.org/"),
        new("firehol-abusers", "FireHOL abusers (24 hours)", "FireHOL", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_1d.netset", 8 * MiB, TimeSpan.FromHours(12), "LOW", "T1110", "Abusive address (24 hours)",
            "Addresses abusing services (spam, brute force, scraping) in the last day.", "Per source (aggregated)", "https://iplists.firehol.org/"),
        new("dshield", "DShield top attackers", "SANS Internet Storm Center", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset", 2 * MiB, TimeSpan.FromHours(12), "MEDIUM", "T1595", "Top attacking network (DShield)",
            "The 20 networks attacking the most sensors worldwide in the last three days.", "Free use (DShield)", "https://isc.sans.edu/"),
        new("bruteforceblocker", "BruteForceBlocker", "Daniel Gerzo / BruteForceBlocker", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bruteforceblocker.ipset", 2 * MiB, TimeSpan.FromHours(24), "LOW", "T1110", "SSH or FTP brute-force source",
            "Addresses caught guessing SSH and FTP passwords.", "Free use", "https://danger.rulez.sk/index.php/bruteforceblocker/"),
        new("ipsum-5", "IPsum (5+ lists)", "Miroslav Stampar", ThreatFeedKinds.Ip, ThreatFeedFormat.Lines,
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt", 4 * MiB, TimeSpan.FromHours(24), "MEDIUM", "T1071", "Address on 5 or more blocklists",
            "Addresses that at least five independent blocklists agree on: very likely malicious.", "Unlicense", "https://github.com/stamparm/ipsum"),
        // Remote access tools (anti-RAT context).
        new("lolrmm", "LOLRMM remote access tools", "LOLRMM Project", ThreatFeedKinds.Lolbin, ThreatFeedFormat.LolRmmJson,
            "https://lolrmm.io/api/rmm_tools.json", 16 * MiB, TimeSpan.FromDays(3), "LOW", "T1219", "Remote access tool",
            "358 remote-control and remote-management programs (AnyDesk, TeamViewer, ScreenConnect and RATs) and their service domains. Scammers and attackers install these to control a PC; shown as context, never as a verdict.", "Apache-2.0", "https://lolrmm.io/"),
        new("ip-origin", "IP origin (country and network)", "IPtoASN", ThreatFeedKinds.Geo, ThreatFeedFormat.Ip2AsnGzip,
            "https://iptoasn.com/data/ip2asn-combined.tsv.gz", 48 * MiB, TimeSpan.FromDays(7), "LOW", "", "",
            "Offline map of every routed address block to its country and network owner, so you can see roughly where connections come from without asking anyone.", "Public domain (PDDL)", "https://iptoasn.com/"),
    ];

    public static ThreatFeedDefinition? Find(string id) => All.FirstOrDefault(feed => feed.Id == id);
}
