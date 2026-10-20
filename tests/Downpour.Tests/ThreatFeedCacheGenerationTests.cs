using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class ThreatFeedCacheGenerationTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "downpour-feed-generation-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void AFullDatasetDoesNotReuseTheOldSubsetCache()
    {
        var cache = new ThreatFeedCache(_directory);
        var full = ThreatFeedCatalog.Find("hagezi-tif")!;
        var old = full with { CacheGeneration = 1 };
        var now = DateTimeOffset.UtcNow;
        cache.Write(old, Encoding.UTF8.GetBytes("subset.example\n"), now);

        Assert.NotNull(cache.TryRead(old, now));
        Assert.Null(cache.TryRead(full, now));
        cache.Write(full, Encoding.UTF8.GetBytes("full.example\n"), now);
        Assert.Contains("full.example", Encoding.UTF8.GetString(cache.TryRead(full, now)!.Value.Payload));
        Assert.Contains("subset.example", Encoding.UTF8.GetString(cache.TryRead(old, now)!.Value.Payload));
    }

    [Fact]
    public void UnchangedSourcesKeepTheirExistingCachePath()
    {
        var feed = ThreatFeedCatalog.Find("threatview-domain")!;
        Assert.Equal(Path.Combine(_directory, feed.Id + ".v1.cache"), new ThreatFeedCache(_directory).PathFor(feed));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1001)]
    public void InvalidGenerationCannotCreateACache(int generation)
    {
        var feed = ThreatFeedCatalog.Find("hagezi-tif")! with { CacheGeneration = generation };
        Assert.Throws<InvalidDataException>(() => new ThreatFeedCache(_directory).PathFor(feed));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }
}
