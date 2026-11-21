using Downpour.Core;

namespace Downpour.Tests;

public sealed class OnboardingStateTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void StateFrom_UnansweredFeedServiceIsNotAFailure()
    {
        var state = OnboardingPlan.StateFrom(false, 0, 0, null, Now, false, false);
        Assert.False(state.FeedsReady);
        Assert.False(state.FirstFeedDownloadFailed);

        var guidance = OnboardingPlan.Next(state);
        Assert.Equal(OnboardingStep.DownloadFeeds, guidance.Step);
        Assert.Contains("Downloading", guidance.Headline);
        Assert.False(guidance.Blocking);
    }

    [Fact]
    public void StateFrom_NoFeedWithEntriesAndOneFailureNamesTheRealFailure()
    {
        var state = OnboardingPlan.StateFrom(true, 0, 2, null, Now, false, false);
        Assert.False(state.FeedsReady);
        Assert.True(state.FirstFeedDownloadFailed);

        var guidance = OnboardingPlan.Next(state);
        Assert.Equal(OnboardingStep.DownloadFeeds, guidance.Step);
        Assert.Contains("did not finish", guidance.Headline);
        Assert.Contains("real failure", guidance.Detail);
    }

    [Fact]
    public void StateFrom_AFeedWithNoEntriesAndNoFailureStaysOnTheDownloadStep()
    {
        var state = OnboardingPlan.StateFrom(true, 0, 0, null, Now, false, false);
        Assert.False(state.FirstFeedDownloadFailed);
        Assert.Equal(OnboardingStep.DownloadFeeds, OnboardingPlan.Next(state).Step);
    }

    [Fact]
    public void StateFrom_ReadyFeedsWithAFreshStoreAskForBaselineTime()
    {
        var state = OnboardingPlan.StateFrom(true, 3, 0, Now.AddHours(-1), Now, false, false);
        Assert.True(state.FeedsReady);
        Assert.False(state.BaselineComplete);
        Assert.Equal(OnboardingStep.EstablishBaseline, OnboardingPlan.Next(state).Step);
    }

    [Fact]
    public void StateFrom_AnUnansweredObservationStartIsNeverABaseline()
    {
        var state = OnboardingPlan.StateFrom(true, 3, 0, null, Now, false, false);
        Assert.False(state.BaselineComplete);
    }

    [Fact]
    public void StateFrom_AFutureObservationStartIsNotABaseline()
    {
        var state = OnboardingPlan.StateFrom(true, 3, 0, Now.AddHours(1), Now, false, false);
        Assert.False(state.BaselineComplete);
    }

    [Fact]
    public void StateFrom_WalksTheFourStepsInOrder()
    {
        var observing = Now.AddHours(-25);
        var baseline = OnboardingPlan.StateFrom(true, 3, 0, observing, Now, false, false);
        Assert.True(baseline.BaselineComplete);

        var permissions = OnboardingPlan.Next(baseline);
        Assert.Equal(OnboardingStep.ConfirmPermissions, permissions.Step);
        Assert.True(permissions.Blocking);

        var quiet = OnboardingPlan.Next(baseline with { PermissionsConfirmed = true });
        Assert.Equal(OnboardingStep.ExplainQuietPeriod, quiet.Step);
        Assert.False(quiet.Blocking);

        var ready = OnboardingPlan.Next(baseline with { PermissionsConfirmed = true, QuietPeriodExplained = true });
        Assert.Equal(OnboardingStep.Ready, ready.Step);
    }

    [Fact]
    public void StateFrom_RefusesNegativeCounts()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => OnboardingPlan.StateFrom(true, -1, 0, null, Now, false, false));
        Assert.Throws<ArgumentOutOfRangeException>(() => OnboardingPlan.StateFrom(true, 0, -1, null, Now, false, false));
    }

    [Fact]
    public void ObservationWindow_IsOneDay()
    {
        Assert.Equal(TimeSpan.FromHours(24), OnboardingPlan.ObservationWindow);
        Assert.True(OnboardingPlan.StateFrom(true, 1, 0, Now - OnboardingPlan.ObservationWindow, Now, false, false).BaselineComplete);
        Assert.False(OnboardingPlan.StateFrom(true, 1, 0, Now - OnboardingPlan.ObservationWindow + TimeSpan.FromMinutes(1), Now, false, false).BaselineComplete);
    }
}
