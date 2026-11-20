namespace Downpour.Core;

public enum OnboardingStep { DownloadFeeds, EstablishBaseline, ConfirmPermissions, ExplainQuietPeriod, Ready }

public sealed record OnboardingState(
    bool FeedsReady,
    bool BaselineComplete,
    bool PermissionsConfirmed,
    bool QuietPeriodExplained,
    bool FirstFeedDownloadFailed);

public sealed record OnboardingGuidance(OnboardingStep Step, string Headline, string Detail, bool Blocking);

/// <summary>
/// A new install is legitimately quiet: feeds download, the baseline is built, sensors start empty. The current screens
/// are honest but read as "it does not work", which is exactly when people uninstall. This computes the next step and
/// says plainly when the quiet period is expected to end, without hiding a real failure behind friendly copy.
/// </summary>
public static class OnboardingPlan
{
    public static OnboardingGuidance Next(OnboardingState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.FeedsReady)
            return state.FirstFeedDownloadFailed
                ? new(OnboardingStep.DownloadFeeds,
                    "The first threat feed download did not finish",
                    "This is a real failure, not the expected quiet start. Check the connection or retry the download; nothing else is being delayed by it.", false)
                : new(OnboardingStep.DownloadFeeds,
                    "Downloading the first threat feeds",
                    "This can take several minutes. The PC is already being watched while the lists arrive.", false);
        if (!state.BaselineComplete)
            return new(OnboardingStep.EstablishBaseline,
                "Learning what is normal on this PC",
                "Autostarts, services and connections are recorded as a baseline. Until that settles, unusually quiet results mean 'nothing has changed yet', not 'nothing is wrong'.", false);
        if (!state.PermissionsConfirmed)
            return new(OnboardingStep.ConfirmPermissions,
                "Two permissions decide what can be seen",
                "Administrator access is what lets Downpour read the security log and autostart locations. Without it, the app stays read-only and several detections cannot run at all.", true);
        if (!state.QuietPeriodExplained)
            return new(OnboardingStep.ExplainQuietPeriod,
                "What the first days should look like",
                "Few or no findings early on is expected. A finding appears when something crosses a threshold; the weekly summary is where slow changes show up first.", false);
        return new(OnboardingStep.Ready, "Setup is complete", "The first baseline is in place and the feeds are current. Findings will appear here as they are confirmed.", false);
    }
}
