using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class FollowUpOperationsTests
{
    [Fact]
    public void MitigationPostureRanksHighValueProcessesFirst()
    {
        var hardened = new ProcessMitigations("chrome", true, true, true, true, true, true);
        var exposed = new ProcessMitigations("notepad", true, false, false, false, false, true);
        var assessment = ExploitMitigationPosture.Assess(hardened);
        Assert.Equal(assessment.Maximum, assessment.Score);
        Assert.Empty(assessment.Gaps);
        Assert.Contains("baseline", ExploitMitigationPosture.Assess(exposed).Verdict);
        var ranked = ExploitMitigationPosture.Rank([exposed, hardened]);
        Assert.Equal("chrome", ranked[0].ProcessName);
        Assert.Equal(2, ranked.Count);
    }

    [Fact]
    public void FeedSchedulingDefersBulkSourcesOnMeteredConnectionsButNotCriticalOnes()
    {
        var now = DateTimeOffset.UtcNow;
        var feeds = new[]
        {
            new FeedDemand("bulk", 400L * 1024 * 1024, TimeSpan.FromHours(12), now.AddDays(-1), false),
            new FeedDemand("fresh", 2L * 1024 * 1024, TimeSpan.FromHours(1), now.AddDays(-1), true),
            new FeedDemand("current", 1L * 1024 * 1024, TimeSpan.FromHours(1), now, false),
        };
        var metered = FeedScheduling.Plan(feeds, now, metered: true);
        Assert.Equal(FeedDecision.DownloadNow, metered.Single(item => item.FeedId == "fresh").Decision);
        Assert.Equal(FeedDecision.DeferMetered, metered.Single(item => item.FeedId == "bulk").Decision);
        Assert.Equal(FeedDecision.NotDue, metered.Single(item => item.FeedId == "current").Decision);
        Assert.Contains("freshness-critical", FeedScheduling.Summarize(metered));

        var limited = FeedScheduling.Plan(feeds, now, metered: false, dailyBudgetBytes: 10L * 1024 * 1024);
        Assert.Equal(FeedDecision.DeferBudget, limited.Single(item => item.FeedId == "bulk").Decision);
    }

    [Fact]
    public void RetentionAccountingNamesCapacityEviction()
    {
        var now = DateTimeOffset.UtcNow;
        var report = StoreRetentionAccounting.Assess(10_000, 10_000, now.AddDays(-5), now, TimeSpan.FromDays(30),
            [new RetentionDay(DateOnly.FromDateTime(now.UtcDateTime), 120)]);
        Assert.Contains(report.Warnings, warning => warning.Contains("capacity"));
        Assert.Contains(report.Warnings, warning => warning.Contains("newer than"));
        Assert.Equal(120, report.EvictedLast7Days);
        var calm = StoreRetentionAccounting.Assess(10, 10_000, now.AddDays(-29), now, TimeSpan.FromDays(30), []);
        Assert.Empty(calm.Warnings);
        Assert.Equal(3, StoreRetentionAccounting.SummarizeByDay([now, now.AddDays(-1), now.AddDays(-1)]).Sum(day => day.EvictedAlerts));
    }

    [Fact]
    public void ExplanationsStateMissingEvidenceAndStayBounded()
    {
        var input = new DetectionExplanationInput("r1", "Suspicious service install", "T1543.003",
            ["EventId", "ServiceName"], ["signature"], "Service binary outside a signed vendor path", 70);
        var text = DetectionExplanation.Build(input);
        Assert.Contains("Not available: signature", text);
        Assert.Contains("70%", text);
        Assert.Contains("Provisional", DetectionExplanation.ConfidenceLabel(input));
        var noisy = input with { ObservedFields = Enumerable.Range(0, 60).Select(index => $"field{index}").ToArray() };
        Assert.True(DetectionExplanation.Build(noisy).Length <= DetectionExplanation.MaximumTextLength);
        Assert.Throws<ArgumentOutOfRangeException>(() => DetectionExplanation.Build(input with { ConfidencePercent = 101 }));
    }

    [Fact]
    public void OnboardingWalksTheStepsInOrder()
    {
        var step = OnboardingPlan.Next(new(false, false, false, false, false));
        Assert.Equal(OnboardingStep.DownloadFeeds, step.Step);
        Assert.Contains("several minutes", step.Detail);
        Assert.Equal(OnboardingStep.DownloadFeeds, OnboardingPlan.Next(new(false, false, false, false, true)).Step);
        Assert.Contains("real failure", OnboardingPlan.Next(new(false, false, false, false, true)).Detail);
        Assert.Equal(OnboardingStep.EstablishBaseline, OnboardingPlan.Next(new(true, false, false, false, false)).Step);
        Assert.True(OnboardingPlan.Next(new(true, true, false, false, false)).Blocking);
        Assert.Equal(OnboardingStep.Ready, OnboardingPlan.Next(new(true, true, true, true, false)).Step);
    }

    [Fact]
    public void UpdateJournalRefusesSkippedTransitionsAndExplainsRecovery()
    {
        var now = DateTimeOffset.UtcNow;
        var downloaded = new UpdateRecord("0.1.26", UpdateState.Downloaded, now, "");
        Assert.Throws<InvalidOperationException>(() => UpdateStagingJournal.Advance(downloaded, UpdateState.Applied, now));
        Assert.Throws<ArgumentException>(() => UpdateStagingJournal.Advance(downloaded, UpdateState.Verified, now));
        var verified = UpdateStagingJournal.Advance(downloaded, UpdateState.Verified, now, "signature and digest match");
        var staged = UpdateStagingJournal.Advance(verified, UpdateState.Staged, now);
        var rolled = UpdateStagingJournal.Advance(staged, UpdateState.RolledBack, now, "new build failed to start");
        Assert.Equal(1, UpdateStagingJournal.CountRollbacks([downloaded, verified, staged, rolled]));
        Assert.Contains("previous build", UpdateStagingJournal.Recover(rolled));
        Assert.Contains("fresh signature check", UpdateStagingJournal.Recover(staged));
        Assert.Contains("No update", UpdateStagingJournal.Recover(null));
    }

    [Fact]
    public void PortableBundleRoundTripsAndExcludesFeedKeys()
    {
        var preview = PortableSettingsBundle.Preview(new(true, true, true, true));
        Assert.False(preview.CanExport == false);
        Assert.Contains(preview.Refusals, refusal => refusal.Contains("credentials"));
        var payload = Encoding.UTF8.GetBytes("""{"suppressions":["rule-a"],"settings":{"hud":true}}""");
        var blob = PortableSettingsBundle.Encrypt("correct horse battery", payload);
        Assert.False(blob.AsSpan().SequenceEqual(payload));
        Assert.Equal(payload, PortableSettingsBundle.Decrypt("correct horse battery", blob));
        Assert.Throws<InvalidDataException>(() => PortableSettingsBundle.Decrypt("wrong horse battery!", blob));
        var tampered = (byte[])blob.Clone();
        tampered[^1] ^= 0xff;
        Assert.Throws<InvalidDataException>(() => PortableSettingsBundle.Decrypt("correct horse battery", tampered));
        Assert.Throws<ArgumentException>(() => PortableSettingsBundle.Encrypt("short", payload));
        Assert.False(PortableSettingsBundle.Preview(new(false, false, false, false)).CanExport);
    }

    [Fact]
    public void WeeklyDigestSaysWhatHappenedAndWhatWaits()
    {
        var now = DateTimeOffset.UtcNow;
        var digest = WeeklyDigest.Build(new DigestInputs(now.AddDays(-7), now, 3, 12, 1, 2, 5, 4, 9, "Suspicious service install"));
        Assert.Contains("3 new autostart", digest);
        Assert.Contains("12 match", digest);
        Assert.Contains("2 sensor", digest);
        Assert.Contains("oldest has been open 9 day", digest);
        Assert.Contains("Suspicious service install", digest);
        var quiet = WeeklyDigest.Build(new DigestInputs(now.AddDays(-7), now, 0, 0, 0, 0, 0, 0, 0, ""));
        Assert.Contains("quiet week", quiet);
        Assert.Contains("Nothing is waiting", quiet);
        Assert.Throws<ArgumentOutOfRangeException>(() => WeeklyDigest.Build(new DigestInputs(now, now.AddDays(-1), 0, 0, 0, 0, 0, 0, 0, "")));
    }
}
