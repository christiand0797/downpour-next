using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Extracts indicators that may be sent to an intel service (SECURITY.md "User-approved data handling"): public IP
/// addresses, MD5/SHA-1/SHA-256 hashes, and domains that the DNS sensor already flagged. Private, loopback,
/// link-local, CGNAT, multicast, and documentation addresses are never returned. Domains are taken only from DNS
/// findings so that file names such as "report.pdf" are never mistaken for domains and sent off the machine.
/// </summary>
public static partial class IntelIndicatorExtractor
{
    public static IReadOnlyList<IntelIndicator> FromAlert(SecurityAlert alert)
    {
        var text = $"{alert.Title} {alert.Provider}";
        var results = new List<IntelIndicator>();
        foreach (Match match in Ipv4().Matches(text))
            if (IPAddress.TryParse(match.Value, out var address) && IsPublic(address)) results.Add(new(IntelKinds.Ip, address.ToString()));
        foreach (Match match in Ipv6().Matches(text))
            if (match.Value.Contains("::") || match.Value.Count(ch => ch == ':') >= 7)
                if (IPAddress.TryParse(match.Value, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6 && IsPublic(address))
                    results.Add(new(IntelKinds.Ip, address.ToString()));
        foreach (Match match in Hash().Matches(alert.Title))
            results.Add(new(IntelKinds.Hash, match.Value.ToLowerInvariant()));
        if (alert.LogName == SecurityFindingCatalog.Dns)
            foreach (Match match in DnsDomain().Matches(alert.Title))
                results.Add(new(IntelKinds.Domain, match.Groups[1].Value.ToLowerInvariant()));
        return results.DistinctBy(indicator => (indicator.Kind, indicator.Value)).ToArray();
    }

    public static bool IsPublic(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return false;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)    // CGNAT
                || (b[0] == 169 && b[1] == 254)                   // link-local
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2)   // IETF / TEST-NET-1
                || (b[0] == 198 && b[1] is 18 or 19)              // benchmarking
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)     // TEST-NET-2
                || (b[0] == 203 && b[1] == 0 && b[2] == 113));    // TEST-NET-3
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv4MappedToIPv6) return IsPublic(address.MapToIPv4());
            var b = address.GetAddressBytes();
            // Only global unicast (2000::/3), excluding documentation 2001:db8::/32.
            return (b[0] & 0xE0) == 0x20 && !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8);
        }
        return false;
    }

    [GeneratedRegex(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])")]
    private static partial Regex Ipv6();

    [GeneratedRegex(@"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")]
    private static partial Regex Hash();

    /// <summary>DNS findings read "DGA-like domain observed in resolver cache: {name} (Risk ...)".</summary>
    [GeneratedRegex(@"resolver cache: ([a-z0-9][a-z0-9.-]{1,252}[a-z0-9]) \(", RegexOptions.IgnoreCase)]
    private static partial Regex DnsDomain();
}
