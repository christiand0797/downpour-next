using System.Net;
using System.Security.Cryptography;
using System.Text;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class ReleaseAndFeedTrustTests
{
    [Fact]
    public void ManifestSignatureAcceptsTheSignerAndRejectsTampering()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfoPem();
        var manifest = Encoding.UTF8.GetBytes("""{"version":"0.1.24","files":[]}""");
        var signature = Convert.ToBase64String(rsa.SignData(manifest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        Assert.Equal(ReleaseSignatureStatus.Valid, ReleaseSignatureVerifier.Verify(manifest, signature, publicKey));
        Assert.Equal(ReleaseSignatureStatus.Invalid, ReleaseSignatureVerifier.Verify(Encoding.UTF8.GetBytes("{}"), signature, publicKey));
        Assert.Equal(ReleaseSignatureStatus.Invalid, ReleaseSignatureVerifier.Verify(manifest, "not-base64", publicKey));
        Assert.Equal(ReleaseSignatureStatus.Invalid, ReleaseSignatureVerifier.Verify(manifest, signature, null));
        Assert.Equal(ReleaseSignatureStatus.Unsigned, ReleaseSignatureVerifier.Verify(manifest, null, publicKey));
    }

    [Fact]
    public void InstallationIntegrityFindsMissingChangedAndUnsafeEntries()
    {
        var root = Directory.CreateTempSubdirectory("downpour-integrity-");
        try
        {
            var file = Path.Combine(root.FullName, "Downpour.Desktop.exe");
            File.WriteAllText(file, "binary");
            var digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))).ToLowerInvariant();
            var expected = new Dictionary<string, string> { ["Downpour.Desktop.exe"] = digest };

            Assert.Empty(InstallationIntegrity.Verify(root.FullName, expected));

            File.WriteAllText(file, "changed");
            var changed = Assert.Single(InstallationIntegrity.Verify(root.FullName, expected));
            Assert.Contains("SHA-256", changed.Problem);

            var missing = Assert.Single(InstallationIntegrity.Verify(root.FullName,
                new Dictionary<string, string> { ["missing.dll"] = digest }));
            Assert.Contains("missing", missing.Problem);

            var unsafeEntry = Assert.Single(InstallationIntegrity.Verify(root.FullName,
                new Dictionary<string, string> { ["../outside.exe"] = digest }));
            Assert.Contains("unsafe", unsafeEntry.Problem, StringComparison.OrdinalIgnoreCase);
        }
        finally { try { root.Delete(recursive: true); } catch (IOException) { } }
    }

    [Theory]
    [InlineData(0, 10_000, true)]
    [InlineData(10_000, 9_000, true)]
    [InlineData(10_000, 2_000, false)]
    [InlineData(10_000, 50_000, false)]
    [InlineData(500, 0, false)]
    [InlineData(500, 900, true)]
    public void FeedUpdateGuardRejectsImplausibleVolumeChanges(int previous, int current, bool accepted)
    {
        Assert.Equal(accepted, FeedUpdateGuard.Assess(previous, current).Accepted);
    }

    [Fact]
    public async Task AuthenticatedFeedSendsTheKeyFromTheProvider()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler);
        var downloader = new ThreatFeedDownloader(http, apiKeyProvider: service =>
            service == ThreatFeedAuth.AbuseCh ? "  test-key  " : null);
        var feed = ThreatFeedCatalog.Find("tweetfeed-domains")! with
        {
            AuthKeyService = ThreatFeedAuth.AbuseCh,
            IndicatorLimit = 10,
        };

        var payload = await downloader.FetchAsync(feed, CancellationToken.None);

        Assert.NotEmpty(payload);
        Assert.Equal("test-key", handler.AuthKey);
    }

    [Fact]
    public async Task UnauthenticatedFeedSendsNoKey()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler);
        var downloader = new ThreatFeedDownloader(http, apiKeyProvider: _ => "should-not-be-sent");

        await downloader.FetchAsync(ThreatFeedCatalog.Find("tweetfeed-domains")!, CancellationToken.None);

        Assert.Null(handler.AuthKey);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public string? AuthKey { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            AuthKey = request.Headers.TryGetValues("Auth-Key", out var values) ? values.FirstOrDefault() : null;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Encoding.UTF8.GetBytes("listed.example\nother.example\n")),
            });
        }
    }
}
