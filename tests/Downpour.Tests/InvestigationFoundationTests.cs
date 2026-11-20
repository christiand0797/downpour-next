using System.IO.Compression;
using System.Text;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class InvestigationFoundationTests
{
    [Fact]
    public void DigestReportsAddedAndRemovedFactsWithAdditionsFirst()
    {
        var changes = LocalChangeDigest.Compare(LocalChangeArea.Service,
            ["Schedule", "Spooler"], ["Spooler", "EvilSvc"]);

        Assert.Equal(2, changes.Count);
        Assert.Equal(new LocalChange(LocalChangeArea.Service, "EvilSvc", "", LocalChangeKind.Added), changes[0]);
        Assert.Equal(LocalChangeKind.Removed, changes[1].Kind);
        Assert.Equal("Schedule", changes[1].Key);
    }

    [Fact]
    public void DigestRanksPersistenceAboveObservations()
    {
        var ranked = LocalChangeDigest.Rank(
        [
            new LocalChange(LocalChangeArea.NetworkDestination, "1.1.1.1", "", LocalChangeKind.Added),
            new LocalChange(LocalChangeArea.Driver, "evil.sys", "", LocalChangeKind.Added),
            new LocalChange(LocalChangeArea.Service, "Svc", "", LocalChangeKind.Added),
        ]);

        Assert.Equal(LocalChangeArea.Driver, ranked[0].Area);
        Assert.Equal(LocalChangeArea.Service, ranked[1].Area);
        Assert.Equal(LocalChangeArea.NetworkDestination, ranked[2].Area);
    }

    [Fact]
    public void EvidenceGraphRequiresKnownEndpointsAndExpandsWithinDepth()
    {
        var graph = new EvidenceGraph();
        Assert.True(graph.AddNode(new("proc:1", "process", "evil.exe")));
        Assert.True(graph.AddNode(new("net:1", "connection", "203.0.113.9:443")));
        Assert.True(graph.AddNode(new("file:1", "file", "payload.dll")));
        Assert.False(graph.AddNode(new("proc:1", "process", "duplicate")));
        Assert.True(graph.AddEdge(new("proc:1", "net:1", "connected")));
        Assert.True(graph.AddEdge(new("proc:1", "file:1", "loaded")));
        Assert.False(graph.AddEdge(new("missing", "proc:1", "connected")));

        var reachable = graph.Reachable("proc:1", depth: 1);
        Assert.Equal(3, reachable.Count);
        Assert.Equal(2, graph.Reachable("file:1", depth: 1).Count);
    }

    [Fact]
    public void GroupingCollapsesRepeatedFindingsAndOrdersBySeverity()
    {
        var groups = AlertGrouping.Group(
        [
            new("feed-a", "host.example", 2, DateTimeOffset.UnixEpoch),
            new("feed-a", "HOST.example", 3, DateTimeOffset.UnixEpoch.AddMinutes(5)),
            new("feed-b", "other.example", 1, DateTimeOffset.UnixEpoch),
            new("feed-c", "third.example", 4, DateTimeOffset.UnixEpoch),
        ]);

        Assert.Equal(3, groups.Count);
        Assert.Equal("feed-c", groups[0].Source);
        Assert.Equal(2, groups.Single(group => group.Source == "feed-a").Count);
        Assert.Equal(3, groups.Single(group => group.Source == "feed-a").HighestSeverityRank);
    }

    [Fact]
    public void ThreatPackRoundTripsAndRejectsTampering()
    {
        using var stream = new MemoryStream();
        ThreatPack.Write(stream, "tests", [("feeds/domains.txt", Encoding.UTF8.GetBytes("a.example\nb.example\n"))]);

        stream.Position = 0;
        var (manifest, files) = ThreatPack.Read(stream);
        Assert.Equal("tests", manifest.CreatedBy);
        Assert.Single(files);
        Assert.Contains("a.example", Encoding.UTF8.GetString(files[0].Content));

        using (var archive = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true))
        {
            var entry = archive.GetEntry("feeds/domains.txt")!;
            using var entryStream = entry.Open();
            entryStream.SetLength(0);
            entryStream.Write(Encoding.UTF8.GetBytes("tampered\n"));
        }
        stream.Position = 0;
        Assert.Throws<InvalidDataException>(() => ThreatPack.Read(stream));
    }

    [Fact]
    public void ThreatPackRejectsUnsafeNames()
    {
        using var stream = new MemoryStream();
        Assert.Throws<InvalidDataException>(() =>
            ThreatPack.Write(stream, "tests", [("../escape.txt", Encoding.UTF8.GetBytes("x"))]));
    }

    [Fact]
    public void RetentionExpiresOnlyPastTheCategoryWindow()
    {
        var policy = new EvidenceRetentionPolicy(30, 180, 7);
        var now = new DateTimeOffset(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);

        Assert.False(EvidenceRetention.IsExpired(now.AddDays(-29), EvidenceCategory.Alert, policy, now));
        Assert.True(EvidenceRetention.IsExpired(now.AddDays(-31), EvidenceCategory.Alert, policy, now));
        Assert.False(EvidenceRetention.IsExpired(now.AddDays(-31), EvidenceCategory.Audit, policy, now));
        Assert.True(EvidenceRetention.IsExpired(now.AddDays(-8), EvidenceCategory.Export, policy, now));
        Assert.False(EvidenceRetention.IsExpired(now.AddDays(1), EvidenceCategory.Alert, policy, now));

        var expired = EvidenceRetention.ExpiredKeys(
        [
            ("old", now.AddDays(-40), EvidenceCategory.Alert),
            ("new", now.AddDays(-1), EvidenceCategory.Alert),
            ("audit", now.AddDays(-40), EvidenceCategory.Audit),
        ], policy, now);
        Assert.Equal(["old"], expired);
    }
}
