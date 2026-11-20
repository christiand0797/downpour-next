using Downpour.Core;

namespace Downpour.Tests;

public sealed class FollowUpDetectionTests
{
    [Fact]
    public void EventCursorOnlyMovesForwardWithinItsChannel()
    {
        var now = DateTimeOffset.UtcNow;
        var first = EventLogContinuity.Advance(null, "System", 100, "hash-a", now);
        Assert.NotNull(first);
        Assert.Null(EventLogContinuity.Advance(first, "System", 100, "hash-a", now));
        Assert.Null(EventLogContinuity.Advance(first, "System", 99, "hash-old", now));
        Assert.Null(EventLogContinuity.Advance(first, "Security", 101, "hash-b", now));
        var advanced = EventLogContinuity.Advance(first, "System", 101, "hash-b", now);
        Assert.Equal(101, advanced!.LastRecordId);
    }

    [Fact]
    public void CatchUpPlanReportsWhatCanBeRecoveredAndWhatWasLost()
    {
        var now = DateTimeOffset.UtcNow;
        var current = EventLogContinuity.Plan(null, "System", 500, 600);
        Assert.Equal(CatchUpOutcome.CatchUp, current.Outcome);
        Assert.Equal(500, current.StartRecordId);

        var cursor = new EventCursor("System", 599, "hash", now);
        Assert.Equal(CatchUpOutcome.CatchUp, EventLogContinuity.Plan(cursor, "System", 500, 620).Outcome);
        Assert.Equal(600, EventLogContinuity.Plan(cursor, "System", 500, 620).StartRecordId);
        Assert.Equal(CatchUpOutcome.Current, EventLogContinuity.Plan(cursor, "System", 500, 599).Outcome);

        var lost = EventLogContinuity.Plan(cursor, "System", 650, 700);
        Assert.Equal(CatchUpOutcome.Lost, lost.Outcome);
        Assert.Equal(50, lost.MissingRecords);
        Assert.Contains("cannot be recovered", lost.Note);

        var other = EventLogContinuity.Plan(cursor, "Security", 1, 5);
        Assert.Equal(CatchUpOutcome.CatchUp, other.Outcome);
        Assert.Equal(1, other.StartRecordId);
    }

    [Fact]
    public void EgressNeedsBothNoveltyAndVolume()
    {
        var baseline = new EgressBaseline();
        var at = DateTimeOffset.UtcNow;
        Assert.Null(baseline.Observe(new EgressSample("chrome", "Contoso ISP", "US", 1_000_000, at)));
        var anomaly = baseline.Observe(new EgressSample("chrome", "Contoso ISP", "US", 100L * 1024 * 1024, at));
        Assert.NotNull(anomaly);
        Assert.Contains("never seen", anomaly.Reason);
        Assert.Null(baseline.Observe(new EgressSample("chrome", "Contoso ISP", "US", 200L * 1024 * 1024, at)));
        Assert.Null(baseline.Observe(new EgressSample("notepad", "Unknown Hosting", "RU", 1_000, at)));
        Assert.Null(baseline.Observe(new EgressSample("notepad", "Unknown Hosting", "RU", 10_000, at)));
    }

    [Fact]
    public void ClockFindingsDistinguishBackwardJumpsFromOrdinaryDrift()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.Equal(ClockVerdict.Unknown,
            ClockIntegrity.Evaluate(new ClockEvidence(now, null, TimeSpan.FromHours(1), null)).Verdict);
        Assert.Equal(ClockVerdict.Consistent,
            ClockIntegrity.Evaluate(new ClockEvidence(now, now.AddMinutes(-2), TimeSpan.FromHours(1), null)).Verdict);
        var backward = ClockIntegrity.Evaluate(new ClockEvidence(now, now.AddMinutes(30), TimeSpan.FromHours(1), null));
        Assert.Equal(ClockVerdict.BackwardJump, backward.Verdict);
        var forward = ClockIntegrity.Evaluate(new ClockEvidence(now, now.AddDays(-3), null, null));
        Assert.Equal(ClockVerdict.ForwardJump, forward.Verdict);
        var mismatch = ClockIntegrity.Evaluate(new ClockEvidence(now, now.AddMinutes(-1), TimeSpan.FromHours(2), now.AddHours(-1)));
        Assert.Equal(ClockVerdict.MonotonicMismatch, mismatch.Verdict);
    }

    [Fact]
    public void CrossViewDiffReportsOneSidedArtifactsAsConsistencyAnomalies()
    {
        var primary = new InventoryView("SCM", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Spooler", "Shared" });
        var secondary = new InventoryView("Registry", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Shared", "HiddenSvc" });
        var anomalies = CrossViewInventory.Compare(primary, secondary, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Spooler" });
        var anomaly = Assert.Single(anomalies);
        Assert.Equal("HiddenSvc", anomaly.Artifact);
        Assert.Contains("not proof", anomaly.Confidence);
        Assert.Contains("not evidence of a rootkit", CrossViewInventory.Summarize(anomalies, "service"));
    }

    [Fact]
    public void RuleCoverageSeparatesCannotFireFromQuiet()
    {
        var rules = new[]
        {
            new RuleRequirement("r-graded", "System", ["EventId", "Provider"]),
            new RuleRequirement("r-missing", "System", ["LogonId"]),
            new RuleRequirement("r-channel", "Security", ["EventId"]),
            new RuleRequirement("r-unknown", "", ["EventId"]),
            new RuleRequirement("r-fired", "System", ["EventId"]),
            new RuleRequirement("r-silent", "System", ["EventId"]),
        };
        var channels = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "System" };
        var fields = new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["System"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "EventId", "Provider" },
        };
        var counts = new Dictionary<string, int> { ["r-graded"] = 1, ["r-fired"] = 4, ["r-silent"] = 0 };

        var coverage = RuleCoverageMap.Assess(rules, channels, fields, counts, DateTimeOffset.UtcNow, TimeSpan.FromDays(30));
        Assert.Equal(RuleState.CannotFire, coverage.Single(item => item.RuleId == "r-missing").State);
        Assert.Equal(RuleState.CannotFire, coverage.Single(item => item.RuleId == "r-channel").State);
        Assert.Equal(RuleState.Unknown, coverage.Single(item => item.RuleId == "r-unknown").State);
        Assert.Equal(RuleState.CanFire, coverage.Single(item => item.RuleId == "r-graded").State);
        Assert.Equal(RuleState.CanFire, coverage.Single(item => item.RuleId == "r-fired").State);
        Assert.Equal(RuleState.Silent, coverage.Single(item => item.RuleId == "r-silent").State);

        var unproven = RuleCoverageMap.Assess(rules.Take(1), channels, fields, new Dictionary<string, int>(), DateTimeOffset.UtcNow);
        Assert.Equal(RuleState.CanFire, Assert.Single(unproven).State);
    }

    [Fact]
    public void ReplayDiffCatchesMissingUnexpectedAndChangedAlerts()
    {
        var expected = new[]
        {
            new ReplayedAlert("a", "High", "r1"),
            new ReplayedAlert("b", "Medium", "r2"),
            new ReplayedAlert("c", "Low", "r3"),
        };
        var actual = new[]
        {
            new ReplayedAlert("a", "High", "r1"),
            new ReplayedAlert("b", "High", "r2"),
            new ReplayedAlert("d", "Medium", "r9"),
        };
        var differences = AlertReplayDiff.Compare(expected, actual);
        Assert.Equal(3, differences.Count);
        Assert.Contains(differences, difference => difference.DedupKey == "b" && difference.Problem.Contains("Severity"));
        Assert.Contains(differences, difference => difference.DedupKey == "c" && difference.Problem.Contains("missing"));
        Assert.Contains(differences, difference => difference.DedupKey == "d" && difference.Problem.Contains("Unexpected"));
        Assert.Empty(AlertReplayDiff.Compare(expected, expected));
    }

    [Fact]
    public void LookalikeDomainsAreDecodedAndNamed()
    {
        var plain = DomainConfusables.Assess("example.com");
        Assert.Empty(plain.LookalikeBrands);
        Assert.False(plain.MixedScript);

        var cyrillic = DomainConfusables.Assess("microsоft.com");
        Assert.Contains("Microsoft", cyrillic.LookalikeBrands);
        Assert.Contains("Cyrillic", cyrillic.Scripts);
        Assert.True(cyrillic.MixedScript);
        Assert.Contains("Lookalike", cyrillic.Verdict);

        var genuine = DomainConfusables.Assess("www.microsoft.com");
        Assert.Empty(genuine.LookalikeBrands);
    }
}
