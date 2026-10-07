using Downpour.Service;

namespace Downpour.Tests;

public sealed class DnsBaselinePrivacyTests
{
    [Fact]
    public void HashIsStableAndCaseInsensitive()
    {
        Assert.Equal(DnsInventoryProvider.HashDomain("Example.COM"), DnsInventoryProvider.HashDomain("example.com"));
        Assert.Matches("^[0-9a-f]{64}$", DnsInventoryProvider.HashDomain("example.com"));
    }

    [Fact]
    public void PlaintextBaselineIsMigratedToHashesAndNoDomainNamesArePersisted()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"downpour-dns-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "dns-baseline.v1.json");
            File.WriteAllText(path, """{"UpdatedUtc":"2026-10-01T00:00:00+00:00","Count":1,"Domains":["private-banking-site.example"]}""");

            new DnsInventoryProvider(path).Capture();

            var stored = File.ReadAllText(path);
            Assert.DoesNotContain("private-banking-site", stored);
            Assert.Contains(DnsInventoryProvider.HashDomain("private-banking-site.example"), stored);
            Assert.DoesNotMatch(@"""[a-z0-9-]+\.[a-z]{2,}""", stored); // no plaintext domain-shaped strings
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
