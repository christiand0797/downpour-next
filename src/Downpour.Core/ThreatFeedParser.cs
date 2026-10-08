using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Downpour.Core;

public enum IndicatorType { Ip, Network, Domain, Sha256, Sha1, Md5, Lolbin }

/// <summary>One validated indicator. Value is normalized (lower-case hashes/domains, canonical IP text).</summary>
public readonly record struct ThreatIndicator(IndicatorType Type, string Value, string Label);

public sealed record ParsedThreatFeed(IReadOnlyList<ThreatIndicator> Indicators, int RejectedLines, IReadOnlyList<ThreatLolbin> Lolbins, IpOriginDatabase? Origins = null)
{
    public int Entries => Indicators.Count + Lolbins.Count + (Origins?.Ranges ?? 0);
}

public sealed record ThreatLolbin(string Name, string Categories, string Techniques);

/// <summary>
/// Strict parsers for allow-listed feed formats. Payloads are data only: nothing is executed, opened or followed.
/// A feed whose lines mostly fail validation is rejected as a whole, so a changed or substituted format cannot
/// silently fill the index with junk.
/// </summary>
public static partial class ThreatFeedParser
{
    public const int MaximumIndicators = 400_000;
    private const int MaximumLabel = 96;
    private const double MaximumRejectedRatio = 0.2;

    public static ParsedThreatFeed Parse(ThreatFeedDefinition feed, ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0) throw new InvalidDataException("The feed is empty.");
        if (payload.Length > feed.MaximumBytes) throw new InvalidDataException("The feed exceeds its size limit.");
        if (feed.Format == ThreatFeedFormat.Ip2AsnGzip) return new ParsedThreatFeed([], 0, [], IpOriginDatabase.Parse(payload));
        var result = feed.Format switch
        {
            ThreatFeedFormat.Lines => ParseLines(feed, Text(payload), hostsFile: false),
            ThreatFeedFormat.HostsFile => ParseLines(feed, Text(payload), hostsFile: true),
            ThreatFeedFormat.UrlLines => ParseUrls(feed, Text(payload)),
            ThreatFeedFormat.FeodoCsv => ParseFeodo(feed, Text(payload)),
            ThreatFeedFormat.SpamhausJsonLines => ParseSpamhaus(feed, Text(payload)),
            ThreatFeedFormat.ThreatFoxJson => ParseThreatFox(feed, payload),
            ThreatFeedFormat.LolDriversJson => ParseLolDrivers(feed, payload),
            ThreatFeedFormat.LolbasJson => ParseLolbas(payload),
            _ => throw new InvalidDataException("Unsupported feed format."),
        };
        var total = result.Indicators.Count + result.Lolbins.Count + result.RejectedLines;
        if (result.Indicators.Count + result.Lolbins.Count == 0) throw new InvalidDataException("The feed contained no valid entries.");
        if (total > 20 && result.RejectedLines > total * MaximumRejectedRatio)
            throw new InvalidDataException($"The feed format looks wrong: {result.RejectedLines:N0} of {total:N0} entries failed validation.");
        return result;
    }

    private static string Text(ReadOnlySpan<byte> payload)
    {
        try { return new UTF8Encoding(false, true).GetString(payload); }
        catch (DecoderFallbackException ex) { throw new InvalidDataException("The feed is not valid UTF-8.", ex); }
    }

    private static List<string> DataLines(string text)
    {
        var lines = new List<string>();
        foreach (var raw in text.AsSpan().EnumerateLines())
        {
            var line = raw.Trim();
            if (line.IsEmpty || line[0] is '#' or ';') continue;
            if (lines.Count >= MaximumIndicators * 2) throw new InvalidDataException("The feed has too many lines.");
            lines.Add(line.ToString());
        }
        return lines;
    }

    private static ParsedThreatFeed ParseLines(ThreatFeedDefinition feed, string text, bool hostsFile)
    {
        var indicators = new List<ThreatIndicator>();
        var rejected = 0;
        foreach (var line in DataLines(text))
        {
            var tokens = line.Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
            var value = hostsFile ? (tokens.Length >= 2 && tokens[0] is "127.0.0.1" or "0.0.0.0" ? tokens[1] : null) : tokens[0];
            if (value is not null && TryClassify(value, out var indicator, feed.DefaultLabel))
            {
                if (indicator.Type == IndicatorType.Domain && SharedPlatforms.IsSharedPlatform(indicator.Value)) continue;
                if (indicator.Type != IndicatorType.Network || !IsReservedNetwork(indicator.Value)) Add(indicators, indicator);
            }
            else if (value is not "localhost") rejected++;
        }
        return new(indicators, rejected, []);
    }

    private static ParsedThreatFeed ParseUrls(ThreatFeedDefinition feed, string text)
    {
        var indicators = new List<ThreatIndicator>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var rejected = 0;
        foreach (var line in DataLines(text))
        {
            if (!Uri.TryCreate(line, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
                !TryClassify(uri.IdnHost, out var indicator, feed.DefaultLabel) || indicator.Type is not (IndicatorType.Domain or IndicatorType.Ip))
            {
                rejected++;
                continue;
            }
            // The malicious part of a URL on a shared platform is its path, not the platform; never index the platform itself.
            if (indicator.Type == IndicatorType.Domain && SharedPlatforms.IsSharedPlatform(indicator.Value)) continue;
            if (seen.Add(indicator.Value)) Add(indicators, indicator);
        }
        return new(indicators, rejected, []);
    }

    private static ParsedThreatFeed ParseFeodo(ThreatFeedDefinition feed, string text)
    {
        var indicators = new List<ThreatIndicator>();
        var rejected = 0;
        foreach (var line in DataLines(text))
        {
            var fields = line.Split(',').Select(f => f.Trim().Trim('"')).ToArray();
            if (fields.Length < 6 || fields[1] == "dst_ip") { if (fields.Length < 6) rejected++; continue; }
            if (TryClassify(fields[1], out var indicator, Label($"Botnet C2 ({Clean(fields[5])})")) && indicator.Type == IndicatorType.Ip) Add(indicators, indicator);
            else rejected++;
        }
        return new(indicators, rejected, []);
    }

    private static ParsedThreatFeed ParseSpamhaus(ThreatFeedDefinition feed, string text)
    {
        var indicators = new List<ThreatIndicator>();
        var rejected = 0;
        foreach (var line in DataLines(text))
        {
            try
            {
                using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 4 });
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object) { rejected++; continue; }
                if (root.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() == "metadata") continue;
                if (root.TryGetProperty("cidr", out var cidr) && cidr.ValueKind == JsonValueKind.String &&
                    TryClassify(cidr.GetString()!, out var indicator, feed.DefaultLabel) && indicator.Type is IndicatorType.Network or IndicatorType.Ip)
                {
                    if (indicator.Type != IndicatorType.Network || !IsReservedNetwork(indicator.Value)) Add(indicators, indicator);
                }
                else rejected++;
            }
            catch (JsonException) { rejected++; }
        }
        return new(indicators, rejected, []);
    }

    private static ParsedThreatFeed ParseThreatFox(ThreatFeedDefinition feed, ReadOnlySpan<byte> payload)
    {
        using var document = ParseJson(payload);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("ThreatFox export is not an object.");
        var indicators = new List<ThreatIndicator>();
        var rejected = 0;
        foreach (var group in document.RootElement.EnumerateObject())
        {
            if (group.Value.ValueKind != JsonValueKind.Array) { rejected++; continue; }
            foreach (var ioc in group.Value.EnumerateArray())
            {
                var value = String(ioc, "ioc_value");
                var type = String(ioc, "ioc_type");
                if (value is null || type is null) { rejected++; continue; }
                if (ioc.TryGetProperty("confidence_level", out var confidence) && confidence.ValueKind == JsonValueKind.Number &&
                    confidence.TryGetInt32(out var level) && level < 50) continue;
                var threat = String(ioc, "threat_type") switch
                {
                    "botnet_cc" => "Malware C2",
                    "payload_delivery" => "Malware delivery",
                    "payload" => "Malware sample",
                    _ => "Malware indicator",
                };
                var malware = String(ioc, "malware_printable") is { Length: > 0 } name && name != "Unknown malware" ? $" ({Clean(name)})" : "";
                var label = Label(threat + malware);
                var candidate = type switch
                {
                    "ip:port" => StripPort(value),
                    "url" => Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri.IdnHost : null,
                    _ => value,
                };
                if (candidate is not null && TryClassify(candidate, out var indicator, label) && Matches(type, indicator.Type) &&
                    !(indicator.Type == IndicatorType.Domain && SharedPlatforms.IsSharedPlatform(indicator.Value)))
                    Add(indicators, indicator);
                else rejected++;
            }
        }
        return new(indicators, rejected, []);

        static bool Matches(string type, IndicatorType parsed) => type switch
        {
            "ip:port" => parsed == IndicatorType.Ip,
            "domain" or "url" => parsed is IndicatorType.Domain or IndicatorType.Ip,
            "sha256_hash" => parsed == IndicatorType.Sha256,
            "sha1_hash" => parsed == IndicatorType.Sha1,
            "md5_hash" => parsed == IndicatorType.Md5,
            _ => false,
        };
    }

    private static ParsedThreatFeed ParseLolDrivers(ThreatFeedDefinition feed, ReadOnlySpan<byte> payload)
    {
        using var document = ParseJson(payload);
        if (document.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("LOLDrivers data is not an array.");
        var indicators = new List<ThreatIndicator>();
        var rejected = 0;
        foreach (var driver in document.RootElement.EnumerateArray())
        {
            if (driver.ValueKind != JsonValueKind.Object || !driver.TryGetProperty("KnownVulnerableSamples", out var samples) || samples.ValueKind != JsonValueKind.Array)
            {
                rejected++;
                continue;
            }
            var malicious = string.Equals(String(driver, "Category"), "malicious", StringComparison.OrdinalIgnoreCase);
            var tag = driver.TryGetProperty("Tags", out var tags) && tags.ValueKind == JsonValueKind.Array && tags.GetArrayLength() > 0 && tags[0].ValueKind == JsonValueKind.String
                ? tags[0].GetString() : null;
            foreach (var sample in samples.EnumerateArray())
            {
                var name = String(sample, "OriginalFilename") is { Length: > 0 } original ? original : String(sample, "Filename") is { Length: > 0 } file ? file : tag ?? "driver";
                var label = Label($"{(malicious ? "Malicious" : "Vulnerable")} driver: {Clean(name)}");
                var any = false;
                foreach (var key in new[] { "SHA256", "SHA1", "MD5" })
                {
                    if (String(sample, key) is { Length: > 0 } hash && TryClassify(hash, out var indicator, label) &&
                        indicator.Type is IndicatorType.Sha256 or IndicatorType.Sha1 or IndicatorType.Md5)
                    {
                        Add(indicators, indicator);
                        any = true;
                    }
                }
                if (!any) rejected++;
            }
        }
        return new(indicators, rejected, []);
    }

    private static ParsedThreatFeed ParseLolbas(ReadOnlySpan<byte> payload)
    {
        using var document = ParseJson(payload);
        if (document.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("LOLBAS data is not an array.");
        var lolbins = new List<ThreatLolbin>();
        var rejected = 0;
        foreach (var entry in document.RootElement.EnumerateArray())
        {
            var name = String(entry, "Name");
            if (name is null || !LolbinName().IsMatch(name)) { rejected++; continue; }
            var categories = new SortedSet<string>(StringComparer.Ordinal);
            var techniques = new SortedSet<string>(StringComparer.Ordinal);
            if (entry.TryGetProperty("Commands", out var commands) && commands.ValueKind == JsonValueKind.Array)
            {
                foreach (var command in commands.EnumerateArray())
                {
                    if (String(command, "Category") is { Length: > 0 and <= 32 } category) categories.Add(Clean(category));
                    if (String(command, "MitreID") is { } mitre && Technique().IsMatch(mitre)) techniques.Add(mitre);
                }
            }
            lolbins.Add(new ThreatLolbin(name.ToLowerInvariant(), Label(string.Join(", ", categories.Take(6))), Label(string.Join(", ", techniques.Take(6)))));
        }
        return new([], rejected, lolbins);
    }

    private static JsonDocument ParseJson(ReadOnlySpan<byte> payload)
    {
        try { return JsonDocument.Parse(payload.ToArray(), new JsonDocumentOptions { MaxDepth = 16, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow }); }
        catch (JsonException ex) { throw new InvalidDataException("The feed is not valid JSON.", ex); }
    }

    private static string? String(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static void Add(List<ThreatIndicator> indicators, ThreatIndicator indicator)
    {
        if (indicators.Count >= MaximumIndicators) throw new InvalidDataException($"The feed has more than {MaximumIndicators:N0} indicators.");
        indicators.Add(indicator);
    }

    private static string? StripPort(string value)
    {
        if (value.StartsWith('[')) return value.IndexOf(']') is var end and > 1 ? value[1..end] : null;
        var colon = value.LastIndexOf(':');
        return colon > 0 && value.IndexOf(':') == colon ? value[..colon] : value;
    }

    /// <summary>Classifies and normalizes one indicator, or returns false. Used for feeds and for user lookups alike.</summary>
    public static bool TryClassify(string raw, out ThreatIndicator indicator, string label = "")
    {
        indicator = default;
        var value = raw.Trim();
        if (value.Length is 0 or > 253) return false;
        if (value.Contains('/'))
        {
            if (IPNetwork.TryParse(value, out var network))
            {
                if (network.PrefixLength == (network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128))
                {
                    indicator = new(IndicatorType.Ip, network.BaseAddress.ToString(), label);
                    return true;
                }
                indicator = new(IndicatorType.Network, network.ToString(), label);
                return true;
            }
            return false;
        }
        if (Ipv4().IsMatch(value) || value.Contains(':'))
        {
            if (!IPAddress.TryParse(value, out var address)) return false;
            indicator = new(IndicatorType.Ip, address.ToString(), label);
            return true;
        }
        if (Hex().IsMatch(value))
        {
            var type = value.Length switch { 64 => IndicatorType.Sha256, 40 => IndicatorType.Sha1, 32 => IndicatorType.Md5, _ => (IndicatorType?)null };
            if (type is null) return false;
            indicator = new(type.Value, value.ToLowerInvariant(), label);
            return true;
        }
        var domain = value.TrimEnd('.').ToLowerInvariant();
        if (!DomainName().IsMatch(domain) || domain.Split('.').Any(l => l.Length is 0 or > 63 || l.StartsWith('-') || l.EndsWith('-'))) return false;
        if (domain.All(c => char.IsAsciiDigit(c) || c == '.')) return false;
        indicator = new(IndicatorType.Domain, domain, label);
        return true;
    }

    /// <summary>Private, loopback, link-local, CGNAT, multicast and other reserved space must never be indexed.</summary>
    public static bool IsReservedNetwork(string cidr) =>
        IPNetwork.TryParse(cidr, out var network) && (IsReserved(network.BaseAddress) || network.PrefixLength < (network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 8 : 16));

    public static bool IsReserved(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] is 0 or 10 or 127 or >= 224 || (b[0] == 100 && b[1] is >= 64 and <= 127) || (b[0] == 169 && b[1] == 254) ||
                   (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2) ||
                   (b[0] == 198 && b[1] is 18 or 19) || (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113);
        }
        return IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast ||
               address.IsIPv6UniqueLocal || address.Equals(IPAddress.IPv6None) || address.Equals(IPAddress.IPv6Any);
    }

    private static string Clean(string value) => new(value.Where(c => !char.IsControl(c)).Take(MaximumLabel).ToArray());

    private static string Label(string value) => value.Length <= MaximumLabel ? value : value[..(MaximumLabel - 1)] + "…";

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$")] private static partial Regex Ipv4();
    [GeneratedRegex(@"^[0-9A-Fa-f]+$")] private static partial Regex Hex();
    [GeneratedRegex(@"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")] private static partial Regex DomainName();
    [GeneratedRegex(@"^[A-Za-z0-9_.-]{1,64}\.(exe|dll|cpl|msc|vbs|js|ps1|bat|cmd|wsf|inf|xsl|sct|hta)$", RegexOptions.IgnoreCase)] private static partial Regex LolbinName();
    [GeneratedRegex(@"^T\d{4}(\.\d{3})?$")] private static partial Regex Technique();
}

/// <summary>
/// Large shared platforms where a malicious URL's path, not the host, is the threat. Indexing such a host would flag
/// ordinary visits to Google Docs or GitHub, because the DNS cache cannot tell a malicious path from a normal one.
/// First-party platforms own every subdomain (docs.google.com), so all of them are skipped. On user-hosting platforms
/// each subdomain belongs to whoever deployed it (evil.vercel.app), so only the bare platform name is skipped.
/// </summary>
public static class SharedPlatforms
{
    private static readonly HashSet<string> FirstParty = new(StringComparer.Ordinal)
    {
        "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "youtube.com", "goo.gl", "forms.gle",
        "microsoft.com", "live.com", "office.com", "office365.com", "onedrive.com", "1drv.ms", "msn.com", "bing.com", "outlook.com", "microsoftonline.com",
        "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "amazon.com",
        // Mobile SDK and app-protection infrastructure that ordinary apps also use; spy apps embedding them does not make them spyware servers.
        "umeng.com", "umengcloud.com", "appjiagu.com", "jiagu.360.cn", "firebase.google.com", "crashlytics.com", "app-measurement.com",
        "dropbox.com", "dropboxusercontent.com", "box.com", "mediafire.com", "mega.nz",
        "discord.com", "discordapp.com", "discordapp.net", "discord.gg", "t.me", "telegram.org", "telegram.me", "whatsapp.com",
        "cloudflare.com", "apple.com", "icloud.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "wikipedia.org",
        "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "pastebin.com", "notion.so", "canva.com", "docusign.net", "adobe.com",
    };

    private static readonly HashSet<string> UserHosting = new(StringComparer.Ordinal)
    {
        "blogspot.com", "sharepoint.com", "windows.net", "azureedge.net", "azurewebsites.net", "cloudfront.net", "r2.dev", "workers.dev", "pages.dev",
        "vercel.app", "netlify.app", "herokuapp.com", "web.app", "firebaseapp.com", "github.io", "notion.site", "weebly.com", "wixsite.com",
        "webflow.io", "glitch.me", "replit.app", "onrender.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org", "000webhostapp.com",
    };

    public static bool IsSharedPlatform(string domain)
    {
        if (UserHosting.Contains(domain)) return true;
        // Bucket and distribution names under amazonaws.com belong to one customer; the S3 service endpoints are shared.
        if (domain.EndsWith(".amazonaws.com", StringComparison.Ordinal) &&
            (domain.StartsWith("s3.", StringComparison.Ordinal) || domain.StartsWith("s3-", StringComparison.Ordinal) || domain.Count(c => c == '.') <= 2))
            return true;
        for (var current = domain; ; )
        {
            if (FirstParty.Contains(current)) return true;
            var dot = current.IndexOf('.');
            if (dot < 0 || current.IndexOf('.', dot + 1) < 0) return false;
            current = current[(dot + 1)..];
        }
    }
}
