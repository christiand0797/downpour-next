namespace Downpour.Contracts;

/// <summary>
/// What the alert store can prove about a week. Every field is a stored count or timestamp: nothing is estimated, and a
/// fact the store does not keep is absent from this record rather than guessed here.
/// </summary>
/// <param name="OldestOpenDays">Null when nothing is open; otherwise the age of the oldest open finding.</param>
/// <param name="ObservedSinceUtc">When channel readability was first recorded, so a short history is not called a week.</param>
public sealed record WeeklyDigestFacts(
    int AlertsFirstSeen,
    int AlertsLastSeen,
    int OpenNow,
    int? OldestOpenDays,
    int AcknowledgedThisWeek,
    int SuppressedThisWeek,
    int SuppressionsActive,
    int HiddenMatches,
    int SuppressionsExpired,
    int EvictionsThisWeek,
    int? SensorsBlind,
    DateTimeOffset? ObservedSinceUtc,
    string? MostActiveRule);
