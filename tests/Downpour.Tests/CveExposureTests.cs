using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class CveExposureTests
{
    private static KevEntry Entry(string cve, string vendor, string product, string added, string name = "Flaw") =>
        new(cve, vendor, product, name, DateOnly.Parse(added), "desc");

    [Theory]
    [InlineData("Microsoft", "Windows", true)]
    [InlineData("Microsoft", "Win32k", true)]
    [InlineData("Microsoft", "Windows SMB", true)]
    [InlineData("Microsoft", "Office", false)]
    [InlineData("Microsoft", "Exchange Server", false)]
    [InlineData("Google", "Chromium V8", false)]
    public void WindowsComponentsAreRecognised(string vendor, string product, bool windows) =>
        Assert.Equal(windows, CveExposure.IsWindows(Entry("CVE-2026-1000", vendor, product, "2026-09-01")));

    [Fact]
    public void WindowsFlawAddedAfterTheLastUpdateIsLikelyMissing()
    {
        var last = new DateTimeOffset(2025, 10, 25, 0, 0, 0, TimeSpan.Zero);
        Assert.True(CveExposure.LikelyMissing(Entry("CVE-2026-1000", "Microsoft", "Windows", "2026-03-10"), last));
        Assert.False(CveExposure.LikelyMissing(Entry("CVE-2025-1000", "Microsoft", "Windows", "2025-09-10"), last));
        // An old CVE added to the catalog late was very likely patched long before the last update.
        Assert.False(CveExposure.LikelyMissing(Entry("CVE-2017-0144", "Microsoft", "Windows SMB", "2026-03-10"), last));
        Assert.False(CveExposure.LikelyMissing(Entry("CVE-2026-2000", "Google", "Chromium", "2026-03-10"), last));
        Assert.False(CveExposure.LikelyMissing(Entry("CVE-2026-1000", "Microsoft", "Windows", "2026-03-10"), null));
    }

    [Fact]
    public void AssessSortsNewestFirstAndAttachesInstalledMatches()
    {
        KevEntry[] catalog = [Entry("CVE-2024-1", "7-Zip", "7-Zip", "2024-01-01"), Entry("CVE-2026-2", "Microsoft", "Windows", "2026-05-01")];
        KevSoftwareCandidate[] candidates = [new("CVE-2024-1", "7-Zip", "7-Zip", "Flaw", new DateOnly(2024, 1, 1), "7-Zip", "23.01", "Igor Pavlov")];

        var assessed = CveExposure.Assess(catalog, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), candidates);

        Assert.Equal("CVE-2026-2", assessed[0].Entry.CveId);
        Assert.True(assessed[0].LikelyMissingOnThisPc);
        Assert.Equal(["7-Zip 23.01"], assessed[1].InstalledMatches);
    }

    [Fact]
    public void AdvisoryLinksAreFixedHosts()
    {
        var entry = Entry("CVE-2026-1000", "Microsoft", "Windows", "2026-09-01");
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2026-1000", CveExposure.NvdUrl(entry.CveId));
        Assert.Equal("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1000", CveExposure.MicrosoftUrl(entry));
        Assert.Null(CveExposure.MicrosoftUrl(entry with { Vendor = "Google" }));
    }

    [Fact]
    public void KevParserKeepsActionDeadlineRansomwareAndNotes()
    {
        const string json = """
        {"title":"t","catalogVersion":"2026.10.08","dateReleased":"2026-10-08","count":1,"vulnerabilities":[
          {"cveID":"CVE-2026-1000","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"Windows Kernel Flaw","dateAdded":"2026-10-01",
           "shortDescription":"d","requiredAction":"Apply mitigations per vendor instructions.","dueDate":"2026-10-22",
           "knownRansomwareCampaignUse":"Known","notes":"https://msrc.microsoft.com/x ; https://nvd.nist.gov/y"}]}
        """;
        var entry = Assert.Single(KevCatalogClient.Parse(Encoding.UTF8.GetBytes(json)).Entries);

        Assert.Equal("Apply mitigations per vendor instructions.", entry.RequiredAction);
        Assert.Equal(new DateOnly(2026, 10, 22), entry.DueDate);
        Assert.True(entry.RansomwareUse);
        Assert.Contains("msrc", entry.Notes);
    }
}
