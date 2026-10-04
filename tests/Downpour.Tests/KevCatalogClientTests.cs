using System.Text;
using Downpour.Core;
using Newtonsoft.Json;

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
    public void ParseRejectsDuplicateJsonPropertiesAndComments()
    {
        var duplicate = ValidCatalog.Replace("\"catalogVersion\":\"2026.10.03\"", "\"catalogVersion\":\"2026.10.03\",\"catalogVersion\":\"forged\"");
        var comment = ValidCatalog.Replace("{\"catalogVersion\"", "{/* untrusted comment */\"catalogVersion\"");

        Assert.Throws<JsonReaderException>(() => KevCatalogClient.Parse(Encoding.UTF8.GetBytes(duplicate)));
        Assert.Throws<JsonReaderException>(() => KevCatalogClient.Parse(Encoding.UTF8.GetBytes(comment)));
    }

    [Fact]
    public void ParseRejectsOversizedPayload()
    {
        var bytes = new byte[KevCatalogClient.MaximumPayloadBytes + 1];

        Assert.Throws<InvalidDataException>(() => KevCatalogClient.Parse(bytes));
    }

    [Fact]
    public void CacheRoundTripsValidatedPayloadAndReportsAge()
    {
        var path = NewCachePath();
        try
        {
            var retrieved = DateTimeOffset.UtcNow.AddHours(-2);
            var payload = Encoding.UTF8.GetBytes(ValidCatalog);
            var snapshot = KevCatalogClient.Parse(payload) with { RetrievedAtUtc = retrieved };
            var cache = new KevCatalogCache(path);

            cache.Write(new KevCatalogDownload(snapshot, payload));
            var cached = cache.TryRead(retrieved.AddHours(2));

            Assert.NotNull(cached);
            Assert.False(cached.IsStale);
            Assert.Equal(retrieved.ToUnixTimeSeconds(), cached.Snapshot.RetrievedAtUtc.ToUnixTimeSeconds());
            Assert.Equal("CVE-2026-12345", Assert.Single(cached.Snapshot.Entries).CveId);
        }
        finally { DeleteCache(path); }
    }

    [Fact]
    public void CacheRejectsTamperedPayload()
    {
        var path = NewCachePath();
        try
        {
            var payload = Encoding.UTF8.GetBytes(ValidCatalog);
            var snapshot = KevCatalogClient.Parse(payload) with { RetrievedAtUtc = DateTimeOffset.UtcNow };
            var cache = new KevCatalogCache(path);
            cache.Write(new KevCatalogDownload(snapshot, payload));
            var bytes = File.ReadAllBytes(path);
            bytes[^1] ^= 0x01;
            File.WriteAllBytes(path, bytes);

            Assert.Throws<InvalidDataException>(() => cache.TryRead());
        }
        finally { DeleteCache(path); }
    }

    [Fact]
    public void CacheRejectsExpiredCatalog()
    {
        var path = NewCachePath();
        try
        {
            var payload = Encoding.UTF8.GetBytes(ValidCatalog);
            var retrieved = DateTimeOffset.UtcNow.Subtract(KevCatalogCache.MaximumAge).AddMinutes(5);
            var snapshot = KevCatalogClient.Parse(payload) with { RetrievedAtUtc = retrieved };
            var cache = new KevCatalogCache(path);
            cache.Write(new KevCatalogDownload(snapshot, payload));

            Assert.Null(cache.TryRead(retrieved.Add(KevCatalogCache.MaximumAge).AddMinutes(10)));
        }
        finally { DeleteCache(path); }
    }

    [Fact]
    public void CacheWriteRejectsUnvalidatedPayload()
    {
        var path = NewCachePath();
        try
        {
            var cache = new KevCatalogCache(path);
            var badPayload = Encoding.UTF8.GetBytes("{\"unexpected\":true}");
            var fakeSnapshot = new KevCatalogSnapshot("1", new DateOnly(2026, 1, 1), DateTimeOffset.UtcNow, []);

            Assert.ThrowsAny<Exception>(() => cache.Write(new KevCatalogDownload(fakeSnapshot, badPayload)));
            Assert.False(File.Exists(path));
        }
        finally { DeleteCache(path); }
    }

    private static string NewCachePath() => Path.Combine(Path.GetTempPath(), "DownpourNextTests", Guid.NewGuid().ToString("N"), "cisa-kev.cache");

    private static void DeleteCache(string path)
    {
        if (File.Exists(path)) File.Delete(path);
        var directory = Path.GetDirectoryName(path);
        if (directory is not null && Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
