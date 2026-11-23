using System.Text;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class AsnReputationTests
{
    private static readonly ThreatFeedDefinition AsnDrop = ThreatFeedCatalog.Find("spamhaus-asn-drop")!;

    private static ParsedThreatFeed Parse(string text) => ThreatFeedParser.Parse(AsnDrop, Encoding.UTF8.GetBytes(text));

    [Fact]
    public void AsnDropReadsListedNetworksAndRejectsMalformedRows()
    {
        var parsed = Parse("""
            {"asn":13335,"rir":"arin","domain":"cloudflare.com","cc":"US","asname":"CLOUDFLARENET"}
            {"asn":9009,"rir":"ripencc","domain":"m247.com","cc":"RO","asname":"M247"}
            {"asn":9009,"rir":"ripencc","cc":"RO","asname":"M247 duplicate"}
            {"asn":0,"rir":"arin","cc":"US","asname":"RESERVED"}
            {"asn":"13335","cc":"US","asname":"wrong type"}
            {"asn":13335,"cc":"US"}
            not json
            """);

        Assert.Equal(2, parsed.Asns!.Count);
        Assert.Empty(parsed.Indicators);
        Assert.Empty(parsed.Lolbins);
        Assert.Equal(4, parsed.RejectedLines);
        Assert.Equal(2, parsed.Entries);
        var m247 = parsed.Asns.Single(a => a.Asn == 9009);
        Assert.Equal("M247", m247.Name);
        Assert.Equal("RO", m247.Country);
        Assert.Equal("ripencc", m247.Registry);
        // The duplicate is ignored without being counted as a rejection.
        Assert.Equal("CLOUDFLARENET", parsed.Asns.Single(a => a.Asn == 13335).Name);
    }

    [Fact]
    public void AMostlyMalformedNetworkListIsRefusedRatherThanPartiallyLoaded()
    {
        var content = string.Join('\n', Enumerable.Range(0, 30).Select(i => i == 0
            ? "{\"asn\":64500,\"cc\":\"US\",\"asname\":\"GOOD\"}"
            : $"{{\"asn\":{i},\"cc\":\"US\"}}"));

        Assert.Throws<InvalidDataException>(() => Parse(content));
    }

    [Fact]
    public void NetworkListingsStayApartFromAddressIndicators()
    {
        var honeypot = ThreatFeedCatalog.Find("mirage-honeypot")!;
        var index = ThreatIndex.Build([
            (AsnDrop, Parse("""{"asn":9009,"rir":"ripencc","cc":"RO","asname":"M247"}""")),
            (honeypot, ThreatFeedParser.Parse(honeypot, Encoding.UTF8.GetBytes("1.2.3.4"))),
        ]);

        Assert.Equal(1, index.AsnListingCount);
        Assert.Equal(1, index.IndicatorCount);
        Assert.Equal("M247", index.Asn(9009)!.Name);
        Assert.Null(index.Asn(13335));
        Assert.Null(index.Asn(null));
        Assert.Empty(index.LookupExact("9009"));
        Assert.Single(index.Lookup(new ThreatIndicator(IndicatorType.Ip, "1.2.3.4", "")));
    }

    [Fact]
    public void TheDescriptionSaysTheListingIsAboutTheNetworkAndNeverTheProgram()
    {
        var index = ThreatIndex.Build([(AsnDrop, Parse("""{"asn":9009,"rir":"ripencc","cc":"RO","asname":"M247"}"""))]);

        var listed = NetworkReputation.Describe(new IpOrigin("1.2.3.4", "RO", 9009, "M247"), index);
        var unlisted = NetworkReputation.Describe(new IpOrigin("1.2.3.4", "US", 13335, "CLOUDFLARENET"), index);
        var unknown = NetworkReputation.Describe(null, index);
        var unnamed = NetworkReputation.Describe(new IpOrigin("1.2.3.4", null, 9009, null), index);

        Assert.Contains("AS9009 M247 (RO)", listed);
        Assert.Contains("Spamhaus ASN-DROP names this network: M247 (RO)", listed);
        Assert.Contains("not evidence about the program", listed);
        Assert.DoesNotContain("ASN-DROP", unlisted);
        Assert.Null(unknown);
        Assert.Contains("unnamed network", unnamed);
        Assert.Equal("M247 (RO)", NetworkReputation.Listing(index, 9009));
        Assert.Null(NetworkReputation.Listing(index, 13335));
        Assert.Null(NetworkReputation.Listing(null, 9009));
    }

    [Fact]
    public void AListedNetworkIsNotAnAutomaticVerdict()
    {
        var index = ThreatIndex.Build([(AsnDrop, Parse("""{"asn":9009,"rir":"ripencc","cc":"RO","asname":"M247"}"""))]);
        var assessment = ThreatVerdictEngine.Assess(new ThreatEvidence(
            ThreatMatchPlaces.Connection, "1.2.3.4", [],
            Program: "app.exe", ProgramPath: @"C:\Program Files\App\app.exe", Signed: true,
            RemotePort: 443, Network: NetworkReputation.Describe(new IpOrigin("1.2.3.4", "RO", 9009, "M247"), index)));

        // A listed network alone is context: nothing was matched in a database, so nothing is called a threat.
        Assert.Equal(ThreatVerdicts.LikelyBenign, assessment.Verdict);
        Assert.Contains(assessment.Reasons, r => r.Contains("Spamhaus ASN-DROP"));
    }
}
