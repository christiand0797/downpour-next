using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class KevCatalogClientTests
{
    private const string ValidCatalog = """
        {"catalogVersion":"2026.10.03","dateReleased":"2026-10-03","count":1,"vulnerabilities":[
          {"cveID":"CVE-2026-12345","vendorProject":"Example Vendor","product":"Example Product","vulnerabilityName":"Example issue","dateAdded":"2026-10-01","shortDescription":"A test record."}
        ]}
        """;

    [Fact]
    public void ParseAcceptsValidatedCisaKevRecord()
    {
        var snapshot = KevCatalogClient.Parse(Encoding.UTF8.GetBytes(ValidCatalog));

        Assert.Equal("2026.10.03", snapshot.CatalogVersion);
        Assert.Equal(new DateOnly(2026, 10, 3), snapshot.ReleasedOn);
        Assert.Single(snapshot.Entries);
        Assert.Equal("CVE-2026-12345", snapshot.Entries[0].CveId);
        Assert.Equal("Example Vendor", snapshot.Entries[0].Vendor);
    }

    [Theory]
    [InlineData("{\"catalogVersion\":\"1\",\"dateReleased\":\"2026-01-01\"}")]
    [InlineData("{\"catalogVersion\":\"1\",\"dateReleased\":\"2026-01-01\",\"vulnerabilities\":[{\"cveID\":\"not-cve\"}]}")]
    [InlineData("{\"catalogVersion\":\"1\",\"dateReleased\":\"not-a-date\",\"vulnerabilities\":[]}")]
    public void ParseRejectsMalformedOrIncompleteCatalog(string json) =>
        Assert.ThrowsAny<Exception>(() => KevCatalogClient.Parse(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void ParseRejectsDuplicateCveIdentifiers()
    {
        var json = """
            {"catalogVersion":"1","dateReleased":"2026-01-01","vulnerabilities":[
              {"cveID":"CVE-2026-12345","vendorProject":"V","product":"P","vulnerabilityName":"N","dateAdded":"2026-01-01"},
              {"cveID":"CVE-2026-12345","vendorProject":"V","product":"P","vulnerabilityName":"N","dateAdded":"2026-01-01"}
            ]}
            """;

        Assert.Throws<InvalidDataException>(() => KevCatalogClient.Parse(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void ParseRejectsOversizedPayload()
    {
        var bytes = new byte[KevCatalogClient.MaximumPayloadBytes + 1];

        Assert.Throws<InvalidDataException>(() => KevCatalogClient.Parse(bytes));
    }
}
