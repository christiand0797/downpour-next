namespace Downpour.Core;

/// <summary>
/// Decides whether a catalogued source may be downloaded. An entry marked retired is kept for historical alert labels;
/// when it also declares an auth service (abuse.ch) it becomes usable as soon as that key is stored. Retirement without
/// an auth service (PhishTank's expiring signed redirect) stays permanent, because no key can make that URL fixed.
/// </summary>
public static class ThreatFeedEnablement
{
    public static bool IsActive(ThreatFeedDefinition feed, Func<string, string?>? keyFor)
    {
        ArgumentNullException.ThrowIfNull(feed);
        if (!feed.Retired) return true;
        return feed.AuthKeyService is { Length: > 0 } service && keyFor?.Invoke(service) is { Length: > 0 };
    }
}
