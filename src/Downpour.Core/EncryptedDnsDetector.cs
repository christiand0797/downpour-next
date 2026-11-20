namespace Downpour.Core;

/// <summary>
/// Recognises connections that carry DNS outside the Windows resolver cache: DNS-over-TLS (port 853) and known
/// DNS-over-HTTPS endpoints on 443. The list is intentionally short and exact; it is a visibility aid, not a
/// blocklist, and an unknown resolver is reported as "encrypted DNS may be in use" rather than guessed at.
/// </summary>
public static class EncryptedDnsDetector
{
    private static readonly string[] DohHosts =
    [
        "dns.google",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "dns.quad9.net",
        "doh.opendns.com",
        "dns.adguard-dns.com",
        "doh.cleanbrowsing.org",
        "dns.nextdns.io",
        "doh.dns.sb",
        "dns.mullvad.net",
    ];

    public static IReadOnlyList<string> KnownDohHosts => DohHosts;

    public static bool IsEncryptedDnsEndpoint(string? host, int port)
    {
        if (port == 853) return true;
        if (port != 443 || string.IsNullOrWhiteSpace(host)) return false;
        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var known in DohHosts)
            if (normalized == known || normalized.EndsWith("." + known, StringComparison.Ordinal))
                return true;
        return false;
    }
}
