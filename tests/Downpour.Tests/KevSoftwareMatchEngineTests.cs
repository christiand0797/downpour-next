using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class KevSoftwareMatchEngineTests
{
    [Fact]
    public void FindsCandidateOnlyWhenVendorAndMeaningfulProductPhrasesMatch()
    {
        var software = new[]
        {
            new InstalledSoftwareEntry("Google Chrome", "124.0", "Google LLC", "Machine"),
            new InstalledSoftwareEntry("Google Update", "1.3", "Google LLC", "Machine"),
            new InstalledSoftwareEntry("Chrome Remote Desktop", "1.0", "Google LLC", "Current user")
        };
        var catalog = new[]
        {
            new KevEntry("CVE-2024-1000", "Google", "Chrome", "Example Chrome issue", new DateOnly(2024, 1, 1), ""),
            new KevEntry("CVE-2024-1001", "Google", "Core", "Generic product name", new DateOnly(2024, 2, 1), "")
        };

        var results = KevSoftwareMatchEngine.FindCandidates(software, catalog, out var limited);

        Assert.False(limited);
        var candidate = Assert.Single(results);
        Assert.Equal("CVE-2024-1000", candidate.CveId);
        Assert.Equal("Google Chrome", candidate.InstalledName);
        Assert.Equal("124.0", candidate.InstalledVersion);
    }

    [Theory]
    [InlineData("16-Core Processor", "AMD", "Core")]
    [InlineData("Intel Graphics Driver", "Intel", "Intel")]
    [InlineData("Company Server Tools", "Company", "Server")]
    public void DoesNotTreatGenericProductOrBareVendorAsCandidate(string installedName, string vendor, string product)
    {
        var software = new[] { new InstalledSoftwareEntry(installedName, "1", vendor, "Machine") };
        var catalog = new[] { new KevEntry("CVE-2024-2000", vendor, product, "Example", new DateOnly(2024, 1, 1), "") };

        Assert.Empty(KevSoftwareMatchEngine.FindCandidates(software, catalog, out _));
    }

    [Fact]
    public void MissingVersionDoesNotTurnCandidateIntoVulnerabilityVerdict()
    {
        var software = new[] { new InstalledSoftwareEntry("Mozilla Firefox", "", "Mozilla Corporation", "Current user") };
        var catalog = new[] { new KevEntry("CVE-2024-3000", "Mozilla", "Firefox", "Example", new DateOnly(2024, 1, 1), "") };

        var candidate = Assert.Single(KevSoftwareMatchEngine.FindCandidates(software, catalog, out _));

        Assert.Equal("", candidate.InstalledVersion);
        Assert.Equal("CVE-2024-3000", candidate.CveId);
    }

    [Fact]
    public void CandidateOutputIsBoundedAndReportsTruncation()
    {
        var software = Enumerable.Range(0, 300).Select(index =>
            new InstalledSoftwareEntry("Mozilla Firefox", index.ToString(), "Mozilla Corporation", "Machine")).ToArray();
        var catalog = Enumerable.Range(0, 2).Select(index =>
            new KevEntry($"CVE-2024-{3000 + index}", "Mozilla", "Firefox", "Example", new DateOnly(2024, 1, 1), "")).ToArray();

        var results = KevSoftwareMatchEngine.FindCandidates(software, catalog, out var limited);

        Assert.Equal(KevSoftwareMatchEngine.MaximumCandidates, results.Count);
        Assert.True(limited);
    }
}
