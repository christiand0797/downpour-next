using Downpour.Core;

namespace Downpour.Tests;

public sealed class FollowUpOperatorFoundationsTests
{
    [Fact]
    public void SourcesAreJudgedOnlyOnReviewedOutcomes()
    {
        var reviewed = Enumerable.Range(0, 20).Select(_ => new DetectionObservation("good-feed", "rule-a", true, false))
            .Concat(Enumerable.Range(0, 10).Select(_ => new DetectionObservation("good-feed", "rule-a", false, true)))
            .Concat(Enumerable.Range(0, 25).Select(_ => new DetectionObservation("noisy-feed", "rule-b", false, true)))
            .Concat(Enumerable.Range(0, 3).Select(_ => new DetectionObservation("new-feed", "rule-c", true, false)))
            .ToArray();

        var values = DetectionValueLedger.Summarize(reviewed);
        Assert.Equal(SourceVerdict.Promote, values.Single(value => value.SourceId == "good-feed").Verdict);
        Assert.Equal(SourceVerdict.Demote, values.Single(value => value.SourceId == "noisy-feed").Verdict);
        Assert.Equal(SourceVerdict.InsufficientEvidence, values.Single(value => value.SourceId == "new-feed").Verdict);
        Assert.Equal(0.667, values.Single(value => value.SourceId == "good-feed").Precision, 3);

        var rules = DetectionValueLedger.SummarizeRules(reviewed, "good-feed", minimumSample: 5);
        Assert.Equal("rule-a", Assert.Single(rules).SourceId);
    }

    [Fact]
    public void SuppressionsExpireCountMatchesAndWarn()
    {
        var now = DateTimeOffset.Parse("2026-11-20T00:00:00Z");
        var suppression = SuppressionPolicy.Grant("System/7045", "channel-provider-event", now, highestSeverityRank: 3);
        Assert.True(SuppressionPolicy.IsActive(suppression, now.AddDays(89)));
        Assert.False(SuppressionPolicy.IsActive(suppression, now.AddDays(91)));

        var counted = SuppressionPolicy.CountMatch(SuppressionPolicy.CountMatch(suppression, 2), 4);
        Assert.Equal(2, counted.MatchesSinceGrant);
        Assert.Equal(4, counted.HighestSeverityRank);
        Assert.Contains(SuppressionPolicy.Warnings([counted], now), warning => warning.Contains("CRITICAL"));

        Assert.Contains(SuppressionPolicy.Warnings([suppression], now.AddDays(85)), warning => warning.Contains("lapses"));
        Assert.Contains(SuppressionPolicy.Warnings([suppression], now.AddDays(95)), warning => warning.Contains("expired"));
        Assert.Throws<ArgumentOutOfRangeException>(() => SuppressionPolicy.Grant("rule", "scope", now, 1, TimeSpan.FromDays(400)));
        Assert.Equal(now.AddDays(120), SuppressionPolicy.Renew(suppression, now.AddDays(30)).ExpiresUtc);
    }

    [Fact]
    public void ChangeLedgerPersistsAcrossRestartsAndDeduplicates()
    {
        var now = DateTimeOffset.Parse("2026-11-20T10:00:00Z");
        var ledger = new ChangeLedger();
        var added = ledger.Append([
            new LocalChange(LocalChangeArea.Autorun, "HKCU\\Run\\x", "", LocalChangeKind.Added),
            new LocalChange(LocalChangeArea.Autorun, "HKCU\\Run\\x", "", LocalChangeKind.Added),
        ], now);
        Assert.Single(added);
        Assert.Empty(ledger.Append([new LocalChange(LocalChangeArea.Autorun, "HKCU\\Run\\x", "", LocalChangeKind.Added)], now.AddMinutes(30)));

        ledger.Append([new LocalChange(LocalChangeArea.Service, "svc", "", LocalChangeKind.Added)], now.AddHours(2));
        Assert.Equal(2, ledger.Count);
        Assert.Single(ledger.Since(now.AddHours(1)));

        var restored = ChangeLedger.Deserialize(ledger.Serialize());
        Assert.Equal(2, restored.Count);
        Assert.Equal(2, restored.Prune(now.AddDays(200)));
        Assert.Equal(0, restored.Count);
        Assert.Equal(0, ChangeLedger.Deserialize("not json").Count);
    }

    [Fact]
    public void AlertsWithoutProvenanceNeverCountAsCurrent()
    {
        var now = DateTimeOffset.Parse("2026-11-20T00:00:00Z");
        var fresh = new AlertProvenance("threatfox", "v1", now.AddHours(-2), "1.2.3.4", "ip");
        var old = fresh with { RetrievedUtc = now.AddDays(-30) };

        Assert.False(AlertProvenancePolicy.IsComplete(AlertProvenancePolicy.Unknown));
        Assert.Equal(EvidenceFreshness.Current, AlertProvenancePolicy.Classify(fresh, now, TimeSpan.FromDays(7)));
        Assert.Equal(EvidenceFreshness.Stale, AlertProvenancePolicy.Classify(old, now, TimeSpan.FromDays(7)));
        Assert.Equal(EvidenceFreshness.Unknown, AlertProvenancePolicy.Classify(AlertProvenancePolicy.Unknown, now, TimeSpan.FromDays(7)));
        Assert.Equal(EvidenceFreshness.Unknown, AlertProvenancePolicy.Classify(fresh with { RetrievedUtc = now.AddDays(1) }, now, TimeSpan.FromDays(7)));
        Assert.Contains("cannot be re-evaluated", AlertProvenancePolicy.Describe(EvidenceFreshness.Unknown, AlertProvenancePolicy.Unknown));
    }

    [Fact]
    public void BlindSpotsAreRankedBySeverityThenFixability()
    {
        var checks = new[]
        {
            new BlindSpotCheck("logs", "Event logs", SensorReadiness.Blind, "Security log not readable", "Join Event Log Readers"),
            new BlindSpotCheck("defender", "Defender", SensorReadiness.Degraded, "Status unavailable", null),
            new BlindSpotCheck("service", "Service", SensorReadiness.Ready, "Online", null),
            new BlindSpotCheck("feeds", "Threat feeds", SensorReadiness.Blind, "Key absent", "Save an abuse.ch key"),
        };
        var ranked = BlindSpotDiagnosis.Rank(checks);
        Assert.Equal(3, ranked.Count);
        Assert.DoesNotContain(ranked, check => check.State == SensorReadiness.Ready);
        Assert.All(ranked.Take(2), check => Assert.Equal(SensorReadiness.Blind, check.State));
        Assert.Contains("2 blind", BlindSpotDiagnosis.Summarize(ranked));
        Assert.Contains("Every checked sensor", BlindSpotDiagnosis.Summarize([]));
    }

    [Fact]
    public void OperationsMetricsReportWorkloadWithoutInventingAcknowledgementTimes()
    {
        var now = DateTimeOffset.Parse("2026-11-20T12:00:00Z");
        var samples = new[]
        {
            new AlertTimingSample("rule-a", now.AddHours(-4), now.AddHours(-3), false),
            new AlertTimingSample("rule-a", now.AddHours(-4), now.AddHours(-2), false),
            new AlertTimingSample("rule-b", now.AddHours(-5), null, true),
            new AlertTimingSample("rule-b", now.AddHours(-6), null, true),
            new AlertTimingSample("rule-a", now.AddHours(-7), null, true),
        };

        var summary = AlertOperationsMetrics.Compute(samples, now);
        Assert.Equal(3, summary.Open);
        Assert.Equal(2, summary.Acknowledged);
        Assert.Equal(TimeSpan.FromHours(1.5), summary.MedianAcknowledge);
        // Nearest-rank p95 over three open ages (5h, 6h, 7h) is the maximum, not the middle sample.
        Assert.Equal(TimeSpan.FromHours(7), summary.P95OpenAge);
        Assert.Equal("rule-a", summary.Noisiest[0].RuleKey);
        Assert.Equal(3, summary.Noisiest[0].Count);

        var empty = AlertOperationsMetrics.Compute([], now);
        Assert.Null(empty.MedianAcknowledge);
        Assert.Null(empty.P95OpenAge);
        Assert.Empty(empty.Noisiest);
    }

    [Fact]
    public void ScannerSupportIsExplicitPerArchitecture()
    {
        Assert.Equal(ScannerCapability.NativeYaraX, ScannerArchitectureSupport.Decide("x64", nativeModulePresent: true, managedFallbackPresent: false));
        Assert.Equal(ScannerCapability.ManagedFallback, ScannerArchitectureSupport.Decide("arm64", nativeModulePresent: false, managedFallbackPresent: true));
        Assert.Equal(ScannerCapability.Unavailable, ScannerArchitectureSupport.Decide("arm64", nativeModulePresent: false, managedFallbackPresent: false));
        Assert.Contains("never as clean", ScannerArchitectureSupport.Describe(ScannerCapability.Unavailable, "arm64"));
        Assert.Contains("limited", ScannerArchitectureSupport.Describe(ScannerCapability.ManagedFallback, "arm64"));
    }

    [Fact]
    public void RescueKitIsReadOnlyAndRefusesChangingSteps()
    {
        var steps = RescueKitPlan.Build(networkAvailable: false, caseExportAvailable: true);
        Assert.All(steps, step => Assert.False(step.ChangesSystem));
        Assert.Empty(RescueKitPlan.ValidateReadOnly(steps));
        var violations = RescueKitPlan.ValidateReadOnly([.. steps, new RescueStep("Clean up", "Delete files", true)]);
        Assert.Single(violations);
        Assert.Contains("changes the system", violations[0]);
        Assert.Contains(steps, step => step.Title.Contains("do not clean up"));
    }

    [Fact]
    public void RefreshBudgetsAreMeasuredAndThrottleQuietly()
    {
        var budgets = RefreshBudget.Evaluate([
            new RefreshSample("dashboard", TimeSpan.FromMilliseconds(80)),
            new RefreshSample("dashboard", TimeSpan.FromMilliseconds(120)),
            new RefreshSample("dashboard", TimeSpan.FromMilliseconds(900)),
            new RefreshSample("alerts", TimeSpan.FromMilliseconds(40)),
        ]);
        var dashboard = budgets.Single(budget => budget.Route == "dashboard");
        Assert.False(dashboard.WithinBudget);
        Assert.Equal(3, dashboard.Samples);
        Assert.Equal(1, RefreshBudget.QuietModeFactor(budgets.Single(budget => budget.Route == "alerts")));
        Assert.InRange(RefreshBudget.QuietModeFactor(dashboard), 2, 10);
        Assert.True(RefreshBudget.Evaluate([new RefreshSample("alerts", TimeSpan.FromMilliseconds(10))]).Single().WithinBudget);
    }
}
