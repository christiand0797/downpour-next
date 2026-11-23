using Downpour.Core;

namespace Downpour.Tests;

public sealed class DomainBaselineTests
{
    private static string Hash(int value) => value.ToString("x64");
    private static string Hex(char value) => new(value, 64);

    [Fact]
    public void TheFirstCaptureIsABaselineAndItsNamesAreNewOnlyOnce()
    {
        var now = DateTimeOffset.UtcNow;
        var empty = new DomainBaseline();

        var first = empty.Observe([Hex('a'), Hex('b')], now);
        Assert.True(first.FirstRun);
        Assert.Equal(2, first.NewHashes.Count);
        Assert.Equal(2, first.Baseline.Count);
        Assert.Null(empty.EstablishedUtc);
        Assert.Equal(now, first.Baseline.EstablishedUtc);

        var second = first.Baseline.Observe([Hex('a'), Hex('b')], now.AddMinutes(5));
        Assert.False(second.FirstRun);
        Assert.Empty(second.NewHashes);
        Assert.Equal(0, second.Evicted);
        Assert.Equal(2, second.Baseline.Count);
    }

    [Fact]
    public void AFreshNameIsNewOnceAndKeepsItsFirstSeenDate()
    {
        var now = DateTimeOffset.UtcNow;
        var seeded = new DomainBaseline().Observe([Hex('a')], now).Baseline;
        var later = now.AddHours(1);

        var update = seeded.Observe([Hex('a'), Hex('b')], later);

        Assert.Equal(new[] { Hex('b') }, update.NewHashes);
        Assert.Equal(later, update.Baseline.FirstSeen(Hex('b')));
        Assert.Equal(now, update.Baseline.FirstSeen(Hex('a')));
        Assert.Empty(update.Baseline.Observe([Hex('a'), Hex('b')], later.AddHours(1)).NewHashes);
    }

    /// <summary>
    /// The regression this baseline replaces: the old code saved an arbitrary <c>Take(n)</c> subset, so a name that stayed
    /// in the resolver cache could fall out and be reported as new again. Eviction is now least-recently-resolved first.
    /// </summary>
    [Fact]
    public void AFullBaselineEvictsTheLeastRecentlyResolvedNameNotAnArbitrarySubset()
    {
        var now = DateTimeOffset.UtcNow;
        var seed = Enumerable.Range(0, DomainBaseline.MinimumCapacity)
            .Select(i => new DomainObservation(Hash(i), now.AddMinutes(i), now.AddMinutes(i)));
        var baseline = new DomainBaseline(seed, DomainBaseline.MinimumCapacity);
        Assert.Equal(DomainBaseline.MinimumCapacity, baseline.Count);

        var today = now.AddDays(1);
        var update = baseline.Observe([Hash(0), Hash(9999)], today, DomainBaseline.MinimumCapacity);

        Assert.Equal(1, update.Evicted);
        Assert.Equal(DomainBaseline.MinimumCapacity, update.Baseline.Count);
        Assert.True(update.Baseline.Knows(Hash(0)));   // resolved again, so it survived
        Assert.True(update.Baseline.Knows(Hash(9999))); // the new name fits
        Assert.False(update.Baseline.Knows(Hash(1)));   // the least recently resolved name left
        Assert.Empty(update.Baseline.Observe([Hash(0), Hash(9999)], today.AddMinutes(1), DomainBaseline.MinimumCapacity).NewHashes);
    }

    [Fact]
    public void MalformedHashesAreIgnoredAndTheCapacityIsBounded()
    {
        var now = DateTimeOffset.UtcNow;
        var update = new DomainBaseline().Observe(["not-a-hash", Hex('a').ToUpperInvariant(), Hex('a'), Hex('a')], now);

        Assert.Equal(new[] { Hex('a') }, update.NewHashes);
        Assert.Equal(1, update.Baseline.Count);
        Assert.Throws<ArgumentOutOfRangeException>(() => new DomainBaseline().Observe([Hex('a')], now, 10));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DomainBaseline().Observe([Hex('a')], now, DomainBaseline.MaximumCapacity + 1));
    }

    [Fact]
    public void TheWrittenOrderIsStableWhateverOrderTheCacheReturns()
    {
        var now = DateTimeOffset.UtcNow;
        var forward = new DomainBaseline().Observe([Hex('a'), Hex('b'), Hex('c')], now).Baseline.Snapshot();
        var reverse = new DomainBaseline().Observe([Hex('c'), Hex('b'), Hex('a')], now).Baseline.Snapshot();

        Assert.Equal(forward.Select(o => o.Hash), reverse.Select(o => o.Hash));
        Assert.Equal(forward.Select(o => o.FirstSeenUtc), reverse.Select(o => o.FirstSeenUtc));
    }
}
