using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Describes the network behind one address using the offline IP-origin table and the ASN-DROP network list. Both are
/// properties of the network's registration and routing, never of the program, the person or the observed behaviour, so
/// the wording says so every time. Nothing here changes a verdict; the text becomes a listed reason a reader can check.
/// </summary>
public static class NetworkReputation
{
    public const int MaximumDescription = 320;
    public const int MaximumListing = 120;

    /// <summary>Country, announcing network and, when listed, the network-owner listing. Null when the ASN is unknown.</summary>
    public static string? Describe(IpOrigin? origin, ThreatIndex? index)
    {
        if (origin?.Asn is not { } asn) return null;
        var name = origin.Network is { Length: > 0 } network ? network : "unnamed network";
        var text = $"AS{asn} {name} ({origin.CountryCode ?? "??"})";
        if (index?.Asn(asn) is { } listing)
            text += $" · Spamhaus ASN-DROP names this network: {listing.Name}" +
                    (listing.Country.Length == 2 ? $" ({listing.Country})" : "") +
                    ". That is a property of the network's routing, not evidence about the program using it";
        return text.Length <= MaximumDescription ? text : text[..MaximumDescription];
    }

    /// <summary>The listing name for display beside a connection, or null when the network is not listed.</summary>
    public static string? Listing(ThreatIndex? index, int? asn)
    {
        if (index?.Asn(asn) is not { } listing) return null;
        var text = listing.Country.Length == 2 ? $"{listing.Name} ({listing.Country})" : listing.Name;
        return text.Length <= MaximumListing ? text : text[..MaximumListing];
    }
}
