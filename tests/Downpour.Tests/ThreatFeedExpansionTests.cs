using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatFeedExpansionTests
{
    private static ThreatFeedDefinition Feed(string id) => ThreatFeedCatalog.Find(id) ?? throw new InvalidOperationException(id);

    private static ParsedThreatFeed Parse(string id, string text) => ThreatFeedParser.Parse(Feed(id), Encoding.UTF8.GetBytes(text));

    [Fact]
    public void CatalogIdsAreUniqueAndFitTheSnapshotLimits()
    {
        Assert.Equal(ThreatFeedCatalog.All.Count, ThreatFeedCatalog.All.Select(f => f.Id).Distinct().Count());
        Assert.InRange(ThreatFeedCatalog.All.Count, 40, 64);
        Assert.All(ThreatFeedCatalog.All, f =>
        {
            Assert.StartsWith("https://", f.Url);
            Assert.InRange(f.Id.Length, 1, 32);
            Assert.InRange(f.Name.Length, 1, 64);
            Assert.InRange(f.Provider.Length, 1, 64);
            Assert.InRange(f.Purpose.Length, 1, 300);
        });
    }

    [Fact]
    public void CsvFeedTakesTheLabelColumn()
    {
        var parsed = Parse("c2intel-ips", "#ip,ioc\n1.15.76.39,Possible Cobaltstrike C2 IP\n101.126.10.34,Possible Sliver C2 IP\n");

        Assert.Equal(2, parsed.Indicators.Count);
        Assert.Contains(parsed.Indicators, i => i.Value == "101.126.10.34" && i.Label == "Possible Sliver C2 IP");
    }

    [Fact]
    public void SemicolonFeedAcceptsMixedIndicators()
    {
        var parsed = Parse("sigbase-c2", "# comment\nsuroot.com;Some APT\n58.64.143.244;Some APT\n");

        Assert.Equal(2, parsed.Indicators.Count);
        Assert.All(parsed.Indicators, i => Assert.Equal("Some APT", i.Label));
    }

    [Fact]
    public void ColumnFeedReadsTheSha256ColumnAndSkipsTheHeader()
    {
        var parsed = Parse("mandiant-redteam",
            "md5,sha1,sha256\n013c7708f1343d684e3571453261b586,5968670c0345b0ab5404bd84cb60d7af7a625020,77bdcb2a9873c4629d8675c8ce9cc8a0cf35c514e27f7a6dc2bc4b31f79dd9e2\n");

        var indicator = Assert.Single(parsed.Indicators);
        Assert.Equal("77bdcb2a9873c4629d8675c8ce9cc8a0cf35c514e27f7a6dc2bc4b31f79dd9e2", indicator.Value);
        Assert.Equal(1, parsed.RejectedLines);
    }

    [Fact]
    public void LolRmmYieldsProgramContextAndServiceDomains()
    {
        const string json = """
        [
          {"Name":"AnyDesk","Category":"RMM","Details":{"PEMetadata":[{"Filename":"anydesk.exe","OriginalFileName":"AnyDesk.exe"}],
            "InstallationPaths":["C:\\Program Files\\AnyDesk\\*","C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe"]},
           "Artifacts":{"Network":[{"Domains":["boot.net.anydesk.com","*.net.anydesk.com"],"Ports":[443]}]}},
          {"Name":"QuasarRAT","Category":"RAT","Details":{"PEMetadata":[{"Filename":"QuasarClient.exe"},{"Filename":"Client.exe"},{"Filename":"dwm.exe"}],"InstallationPaths":[]},"Artifacts":{"Network":[]}}
        ]
        """;
        var parsed = Parse("lolrmm", json);

        Assert.Contains(parsed.Lolbins, l => l.Name == "anydesk.exe" && l.Categories.Contains("AnyDesk") && l.Techniques == "T1219");
        Assert.Contains(parsed.Lolbins, l => l.Name == "quasarclient.exe" && l.Categories.StartsWith("Remote access trojan"));
        Assert.DoesNotContain(parsed.Lolbins, l => l.Name is "client.exe" or "dwm.exe");
        Assert.Contains(parsed.Indicators, i => i.Value == "boot.net.anydesk.com");
        Assert.Contains(parsed.Indicators, i => i.Value == "net.anydesk.com");
    }

    /// <summary>Downloads every feed added in this expansion and parses it. Opt-in: set DOWNPOUR_LIVE_FEEDS=1.</summary>
    [Fact]
    public async Task LiveFeedsDownloadAndParse()
    {
        if (Environment.GetEnvironmentVariable("DOWNPOUR_LIVE_FEEDS") != "1") return;
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(90) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("DownpourNext-test");
        var failures = new List<string>();
        foreach (var feed in ThreatFeedCatalog.All.Where(f => f.Format != ThreatFeedFormat.Ip2AsnGzip))
        {
            try
            {
                var bytes = await http.GetByteArrayAsync(feed.Url);
                var parsed = ThreatFeedParser.Parse(feed, bytes);
                Console.WriteLine($"{feed.Id}: {parsed.Indicators.Count} indicators, {parsed.Lolbins.Count} programs, {parsed.RejectedLines} rejected");
            }
            catch (Exception ex) { failures.Add($"{feed.Id}: {ex.Message}"); }
        }
        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }
}
