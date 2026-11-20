namespace Downpour.Core;

/// <summary>
/// Services whose free API key authenticates a threat-feed download. Kept apart from <c>IntelServices</c> because
/// these keys are used by the sensor for bulk downloads, not by the interactive lookup UI.
/// </summary>
public static class ThreatFeedAuth
{
    public const string AbuseCh = "abuse.ch";

    /// <summary>The header abuse.ch uses for authenticated exports.</summary>
    public const string AbuseChHeader = "Auth-Key";

    public static string? HeaderFor(string service) => service == AbuseCh ? AbuseChHeader : null;
}
