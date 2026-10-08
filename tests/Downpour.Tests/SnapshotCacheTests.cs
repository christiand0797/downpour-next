using Downpour.Service;

namespace Downpour.Tests;

public sealed class SnapshotCacheTests
{
    private sealed record Sample(int Number);

    [Fact]
    public async Task FirstRequestWaitsThenRepeatsAreServedFromCache()
    {
        var captures = 0;
        var cache = new SnapshotCache<Sample>(() => new Sample(Interlocked.Increment(ref captures)), TimeSpan.FromMinutes(5));
        Assert.Equal(1, (await cache.GetAsync(default)).Number);
        for (var i = 0; i < 20; i++) Assert.Equal(1, (await cache.GetAsync(default)).Number);
        Assert.Equal(1, captures);
    }

    [Fact]
    public async Task StaleSnapshotIsServedImmediatelyWhileOneRefreshRuns()
    {
        var captures = 0;
        using var release = new ManualResetEventSlim(true);
        var cache = new SnapshotCache<Sample>(() =>
        {
            var number = Interlocked.Increment(ref captures);
            release.Wait(TimeSpan.FromSeconds(10));
            return new Sample(number);
        }, TimeSpan.Zero);
        Assert.Equal(1, (await cache.GetAsync(default)).Number);

        release.Reset(); // the next capture is slow
        var stale = await cache.GetAsync(default).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1, stale.Number); // did not wait for the slow capture
        for (var attempt = 0; attempt < 200 && Volatile.Read(ref captures) < 2; attempt++) await Task.Delay(10);
        for (var i = 0; i < 10; i++) Assert.Equal(1, (await cache.GetAsync(default)).Number);
        Assert.Equal(2, Volatile.Read(ref captures)); // only one background capture at a time
        release.Set();

        for (var attempt = 0; attempt < 100 && (await cache.GetAsync(default)).Number < 2; attempt++) await Task.Delay(20);
        Assert.True((await cache.GetAsync(default)).Number >= 2);
    }

    [Fact]
    public async Task FailedRefreshKeepsServingThePreviousSnapshot()
    {
        var fail = false;
        var cache = new SnapshotCache<Sample>(() => fail ? throw new InvalidOperationException("collector failed") : new Sample(7), TimeSpan.Zero);
        Assert.Equal(7, (await cache.GetAsync(default)).Number);
        fail = true;
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(7, (await cache.GetAsync(default)).Number);
            await Task.Delay(10);
        }
    }

    [Fact]
    public async Task FirstCaptureFailureIsReported()
    {
        var cache = new SnapshotCache<Sample>(() => throw new InvalidOperationException("collector failed"), TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cache.GetAsync(default));
    }
}
