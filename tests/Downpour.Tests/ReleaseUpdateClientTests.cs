using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ReleaseUpdateClientTests
{
    [Fact]
    public void ParseLatestRelease_RequiresFixedRepositoryAndExactAsset()
    {
        var release = ReleaseUpdateClient.ParseLatestRelease(Encoding.UTF8.GetBytes(ValidReleaseJson()));

        Assert.Equal(new Version(0, 1, 10), release.Version);
        Assert.Equal("v0.1.10", release.Tag);
        Assert.Equal("A".Repeat(64), release.Sha256);
        Assert.Equal(1024, release.Size);
        Assert.True(release.DownloadUri.IsHttps());
    }

    [Theory]
    [InlineData("\"prerelease\":false", "\"prerelease\":true")]
    [InlineData("christiand0797/downpour-next", "attacker/downpour-next")]
    [InlineData("DownpourNext-win-x64-0.1.10.zip", "DownpourNext-win-x64-0.1.9.zip")]
    [InlineData("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void ParseLatestRelease_RejectsInvalidReleaseFields(string original, string replacement)
    {
        var json = ValidReleaseJson().Replace(original, replacement, StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => ReleaseUpdateClient.ParseLatestRelease(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void ParseLatestRelease_RejectsDuplicateTrustFields()
    {
        var json = ValidReleaseJson().Replace("\"draft\":false", "\"draft\":false,\"draft\":true", StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => ReleaseUpdateClient.ParseLatestRelease(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void CheckResultOnlyIncludesPackageWhenVersionIsNewer()
    {
        var latest = ReleaseUpdateClient.ParseLatestRelease(Encoding.UTF8.GetBytes(ValidReleaseJson()));
        Assert.True(latest.Version > new Version(0, 1, 9));
        Assert.False(latest.Version > new Version(0, 1, 10));
    }

    [Fact]
    public async Task DownloadVerifiedPackage_EnforcesDigestAndDeletesBadPartialFile()
    {
        var bytes = Encoding.UTF8.GetBytes("verified update bytes");
        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        var release = new DownpourRelease(new Version(0, 1, 10), "v0.1.10",
            new Uri("https://github.com/christiand0797/downpour-next/releases/download/v0.1.10/DownpourNext-win-x64-0.1.10.zip"),
            digest, bytes.Length, "https://github.com/christiand0797/downpour-next/releases/tag/v0.1.10");
        var root = Path.Combine(Path.GetTempPath(), "downpour-download-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using (var client = new ReleaseUpdateClient(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }))))
            {
                var target = Path.Combine(root, "good.zip");
                await client.DownloadVerifiedPackageAsync(release, target);
                Assert.Equal(bytes, await File.ReadAllBytesAsync(target));
            }

            using (var client = new ReleaseUpdateClient(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes("tampered")) }))))
            {
                var target = Path.Combine(root, "bad.zip");
                await Assert.ThrowsAsync<InvalidDataException>(() => client.DownloadVerifiedPackageAsync(release, target));
                Assert.False(File.Exists(target));
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task DownloadVerifiedPackage_RejectsRedirectToUntrustedHost()
    {
        var release = new DownpourRelease(new Version(0, 1, 10), "v0.1.10",
            new Uri("https://github.com/christiand0797/downpour-next/releases/download/v0.1.10/DownpourNext-win-x64-0.1.10.zip"),
            "A".Repeat(64), 1, "https://github.com/christiand0797/downpour-next/releases/tag/v0.1.10");
        using var client = new ReleaseUpdateClient(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri("https://attacker.example/update.zip") }
        })));
        var target = Path.Combine(Path.GetTempPath(), "downpour-redir-test-" + Guid.NewGuid().ToString("N"));
        await Assert.ThrowsAsync<InvalidDataException>(() => client.DownloadVerifiedPackageAsync(release, target));
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void ExtractToStage_ExtractsRequiredFilesAndRejectsPathTraversal()
    {
        var root = Path.Combine(Path.GetTempPath(), "downpour-update-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var archivePath = Path.Combine(root, "good.zip");
            using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
            {
                Add(archive, "Downpour.Desktop.exe", "desktop");
                Add(archive, "service/Downpour.Service.exe", "service");
            }
            var goodStage = Path.Combine(root, "good-stage");
            var hashes = UpdateArchive.ExtractToStage(archivePath, goodStage);
            Assert.Equal(2, hashes.Count);
            Assert.Equal("desktop", File.ReadAllText(Path.Combine(goodStage, "Downpour.Desktop.exe")));

            var maliciousPath = Path.Combine(root, "bad.zip");
            using (var archive = ZipFile.Open(maliciousPath, ZipArchiveMode.Create))
            {
                Add(archive, "Downpour.Desktop.exe", "desktop");
                Add(archive, "service/Downpour.Service.exe", "service");
                Add(archive, "../outside.txt", "escape");
            }
            var badStage = Path.Combine(root, "bad-stage");
            Assert.Throws<InvalidDataException>(() => UpdateArchive.ExtractToStage(maliciousPath, badStage));
            Assert.False(File.Exists(Path.Combine(root, "outside.txt")));
            Assert.False(Directory.Exists(badStage));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void Add(ZipArchive archive, string name, string contents)
    {
        using var writer = new StreamWriter(archive.CreateEntry(name).Open());
        writer.Write(contents);
    }

    private static string ValidReleaseJson() => """
        {
          "tag_name":"v0.1.10",
          "draft":false,
          "prerelease":false,
          "html_url":"https://github.com/christiand0797/downpour-next/releases/tag/v0.1.10",
          "assets":[{
            "name":"DownpourNext-win-x64-0.1.10.zip",
            "state":"uploaded",
            "content_type":"application/zip",
            "size":1024,
            "digest":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "browser_download_url":"https://github.com/christiand0797/downpour-next/releases/download/v0.1.10/DownpourNext-win-x64-0.1.10.zip"
          }]
        }
        """;
}

internal sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> callback) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(callback(request));
}

internal static class UpdateTestExtensions
{
    public static string Repeat(this string value, int count) => string.Concat(Enumerable.Repeat(value, count));
    public static bool IsHttps(this Uri uri) => uri.Scheme == Uri.UriSchemeHttps;
}
