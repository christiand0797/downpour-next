using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class CognitiveImmuneSystemCoordinatorTests
{
    [Fact]
    public void MissingSourcesRemainUnknown()
    {
        var result = CognitiveImmuneSystemCoordinator.Assess(null, null, null);
        Assert.Equal("Unavailable", result.Status);
        Assert.Null(result.OpenAlerts);
        Assert.Null(result.UrgentOpenAlerts);
        Assert.Null(result.StoredAlerts);
        Assert.Null(result.ObservedTechniques);
        Assert.Empty(result.RecentAlerts);
        Assert.Empty(result.Correlations);
        Assert.Contains(result.Warnings, w => w.Contains("not absence"));
        var report = CognitiveImmuneSystemCoordinator.CreateReport(result, null);
        Assert.Contains("unknown", report);
        Assert.Contains("not checked", report);
        Assert.DoesNotContain("94%", report);
    }

    [Fact]
    public void CountsRespectStateVerificationAndReturnedWindow()
    {
        var rows = new[] { Alert('a', "Open", true), Alert('b', "Acknowledged", true), Alert('c', "Suppressed", true), Alert('d', "Open", false) };
        var result = CognitiveImmuneSystemCoordinator.Assess(new(1, DateTimeOffset.UtcNow, 9000, rows, []), null, new(1, false, false));
        Assert.Equal(9000, result.StoredAlerts);
        Assert.Equal(4, result.ReviewedAlerts);
        Assert.Equal(2, result.OpenAlerts);
        Assert.Equal(2, result.UrgentOpenAlerts);
        Assert.Equal(2, result.VerifiedActiveAlerts);
        Assert.Equal(1, result.SuppressedAlerts);
        Assert.Equal(1, result.ObservedTechniques);
        Assert.Contains(result.Warnings, w => w.Contains("truncated"));
        Assert.Contains(result.Sources, s => s.Name.Contains("PowerShell") && s.Status == "Disabled");
    }

    [Fact]
    public void MalformedAndStaleSnapshotsAreNotCounted()
    {
        var now = DateTimeOffset.UtcNow;
        var stale = new SecurityAlertSnapshot(1, now.AddHours(-1), 0, [], []);
        Assert.Null(CognitiveImmuneSystemCoordinator.Assess(stale, null, null).ReviewedAlerts);
        var forged = new SecurityAlertSnapshot(1, now, 1, [Alert('a', "Open", false) with { Title = "Forged malware" }], []);
        Assert.Null(CognitiveImmuneSystemCoordinator.Assess(forged, null, null).UrgentOpenAlerts);
    }

    [Fact]
    public void EmptyValidWindowReportsZeroWithoutProtectionVerdict()
    {
        var result = CognitiveImmuneSystemCoordinator.Assess(new(1, DateTimeOffset.UtcNow, 0, [], ["AMSI unavailable"]), null, null);
        Assert.Equal(0, result.OpenAlerts);
        Assert.Equal("Partial", result.Status);
        Assert.Contains("AMSI unavailable", result.Warnings);
        Assert.Contains("does not measure containment", CognitiveImmuneSystemCoordinator.CreateReport(result, null));
    }

    [Fact]
    public void RecentWindowIsBoundedAndSorted()
    {
        var rows = Enumerable.Range(1, 50).Select(i => Alert('a', "Open", false) with { AlertId = i.ToString("x64"), LastSeenUtc = DateTimeOffset.UtcNow.AddSeconds(-i) }).ToArray();
        var result = CognitiveImmuneSystemCoordinator.Assess(new(1, DateTimeOffset.UtcNow, 50, rows, []), null, null);
        Assert.Equal(32, result.RecentAlerts.Count);
        Assert.Equal(rows[0].AlertId, result.RecentAlerts[0].AlertId);
    }

    [Fact]
    public void ReportIncludesMatureAggregateBaselineAndInvestigationScope()
    {
        var learning = Learning(cpu: 95);
        var report = Report(learning);

        Assert.Contains("## Local learning at review time", report);
        Assert.Contains("state: attention", report);
        Assert.Contains("cpu: unusual; current 95.0%; normal 10.0%; unusual above 20.0%; 24 observed buckets (baseline available)", report);
        Assert.Contains("connections: typical; current 10.0; normal 10.0; unusual above 25.0", report);
        Assert.Contains("Investigation: Inspect unusual resource pressure", report);
        Assert.Contains("Open: processes.", report);
        Assert.Contains("No API/LLM or automatic fixes", report);
        Assert.Contains("Baselines are not a protection score", report);
        Assert.Contains("temporal co-occurrence does not prove causation", report);
    }

    [Fact]
    public void ReportKeepsUntrainedBaselineUnknown()
    {
        var report = Report(Learning(buckets: 0));

        Assert.Contains("state: learning", report);
        Assert.Contains("cpu: learning; current 10.0%; normal unknown; unusual above unknown; 0 observed buckets (collecting baseline)", report);
        Assert.Contains("at least 24 completed observed buckets per metric", report);
        Assert.Contains("Missing time is not filled with zeroes", report);
        Assert.Contains("this is not a protection guarantee", report);
        Assert.DoesNotContain("normal 0.0", report);
    }

    [Fact]
    public void ReportDistinguishesPausedHistoryFromCurrentMeasurements()
    {
        var report = Report(Learning(cpu: 95, enabled: false));

        Assert.Contains("state: paused", report);
        Assert.Contains("Learning was paused in Settings at review time", report);
        Assert.Contains("Retained baselines are historical", report);
        Assert.Contains("cpu: paused; current unknown; normal 10.0%; unusual above 20.0%", report);
        Assert.DoesNotContain("current 95.0", report);
        Assert.DoesNotContain("Investigation:", report);
        Assert.DoesNotContain("No investigation was recommended", report);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReportPreservesPartialOrUnavailableTelemetry(bool unavailable)
    {
        var learning = Learning(cpu: null);
        if (unavailable)
            learning = LocalLearningEngine.Assess(LocalLearningEngine.Empty, null, new(1, ReviewTime, 0, [], []), ReviewTime);
        var report = Report(learning);

        Assert.Contains(unavailable ? "state: unavailable" : "state: partial", report);
        Assert.Contains("cpu: unavailable; current unknown", report);
        Assert.Contains("missing readings must not be interpreted as healthy or quiet", report);
        if (unavailable) Assert.Contains("Learning warning: Current aggregate telemetry is unavailable or stale", report);
    }

    [Fact]
    public void ReportWithoutLearningDoesNotInventMeasurements()
    {
        var report = Report(null);

        Assert.Contains("Local learning: unavailable", report);
        Assert.Contains("readings and recommendations are unknown", report);
        Assert.DoesNotContain("- cpu:", report);
        Assert.DoesNotContain("Investigation:", report);
    }

    [Theory]
    [InlineData(-121)]
    [InlineData(1)]
    [InlineData(61)]
    public void ReportRejectsLearningFromOutsideTheCapturedReview(int secondsFromReview)
    {
        var learning = Learning() with
        {
            CapturedAtUtc = ReviewTime.AddSeconds(secondsFromReview),
            Recommendations = [new("rejected", "Excluded recommendation", "Must not be copied into this review", "network")]
        };
        var report = Report(learning);

        Assert.Contains("Local learning: unavailable", report);
        Assert.DoesNotContain("- cpu:", report);
        Assert.DoesNotContain("Excluded recommendation", report);
    }

    [Fact]
    public void ReportRejectsAnObservationAfterItsSnapshotCapture()
    {
        var learning = Learning() with { LastObservationUtc = ReviewTime.AddSeconds(1) };
        Assert.True(LocalLearningClient.IsValid(learning, ReviewTime)); // Transport permits clock tolerance.

        var report = Report(learning);

        Assert.Contains("Local learning: unavailable", report);
        Assert.DoesNotContain("- cpu:", report);
    }

    [Fact]
    public void ReportUsesReviewTimeRatherThanTimeOfCopy()
    {
        // This review is deliberately historical. Copying it later must not silently
        // drop its measurements or substitute a newer service snapshot.
        var learning = Learning() with { CapturedAtUtc = ReviewTime.AddMinutes(-2) };
        var report = Report(learning);

        Assert.Contains($"Captured UTC: {learning.CapturedAtUtc:O}; state: observing", report);
        Assert.Contains("cpu: typical; current 10.0%; normal 10.0%", report);
        Assert.DoesNotContain("Local learning: unavailable", report);
    }

    [Fact]
    public void ReportRejectsMalformedLearningWithoutLeakingAnyDraftValues()
    {
        var good = Learning();
        var malformed = new[]
        {
            good with { SchemaVersion = 99 },
            good with { Metrics = null! },
            good with { Metrics = [null!, null!, null!, null!] },
            good with { Metrics = good.Metrics.Select(m => m with { Current = double.NaN }).ToArray() },
            good with { State = "fully-protected" },
            good with { Warnings = ["forged\n# status"] },
            good with { Recommendations = [new("x", "Invalid route", "Not an allowed investigation", "cmd.exe")] }
        };

        foreach (var learning in malformed)
        {
            var report = Report(learning);
            Assert.Contains("Local learning: unavailable", report);
            Assert.DoesNotContain("- cpu:", report);
            Assert.DoesNotContain("fully-protected", report);
            Assert.DoesNotContain("cmd.exe", report);
            Assert.DoesNotContain("forged", report);
        }
    }

    [Fact]
    public void ReportEscapesLearningTextAndKeepsFixedInvestigationRoute()
    {
        var learning = Learning() with
        {
            Warnings = ["A <source> needs [review]"],
            Recommendations = [new("review", "Inspect [source]", "Review <evidence> and `details`", "security-events")]
        };
        var report = Report(learning);

        Assert.Contains("Learning warning: A &lt;source&gt; needs \\[review\\]", report);
        Assert.Contains("Investigation: Inspect \\[source\\]. Review &lt;evidence&gt; and \\`details\\` Open: security-events.", report);
        Assert.DoesNotContain("<evidence>", report);
    }

    private static readonly DateTimeOffset ReviewTime = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

    private static string Report(LocalLearningSnapshot? learning)
    {
        var assessment = CognitiveImmuneSystemCoordinator.Assess(null, null, null) with { CapturedAtUtc = ReviewTime };
        return CognitiveImmuneSystemCoordinator.CreateReport(assessment, null, learning);
    }

    private static LocalLearningSnapshot Learning(int buckets = 24, double? cpu = 10, bool enabled = true)
    {
        var history = LocalLearningEngine.Empty;
        for (var i = buckets; i > 0; i--)
        {
            var at = ReviewTime.AddMinutes(-5 * i);
            history = LocalLearningEngine.Observe(history, new(at, 10, 40, 10, 100), at);
        }
        return LocalLearningEngine.Assess(history, new(ReviewTime, cpu, 40, 10, 100),
            new(1, ReviewTime, 0, [], []), ReviewTime, enabled);
    }

    private static SecurityAlert Alert(char id, string state, bool verified)
    {
        var now = DateTimeOffset.UtcNow;
        SecurityEventCatalog.TryGetRule("System", 7045, out var rule);
        return new(new string(id, 64), rule.Summary, rule.Severity, rule.Technique, "System", "Service Control Manager", 7045,
            id, now.AddMinutes(-2), now.AddMinutes(-2), now.AddMinutes(-1), 1, state, verified);
    }
}
