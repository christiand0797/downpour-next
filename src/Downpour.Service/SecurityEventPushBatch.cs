using Downpour.Contracts;

namespace Downpour.Service;

internal static class SecurityEventPushBatch
{
    public static SecurityEventSnapshot Merge(
        SecurityEventSnapshot current,
        IReadOnlyCollection<SecurityEventObservation> pushed,
        DateTimeOffset capturedAtUtc,
        IEnumerable<string> subscriptionWarnings)
    {
        var events = current.Events.Concat(pushed.Take(256))
            .Where(item => item.CreatedAtUtc is { } time && time <= capturedAtUtc.AddMinutes(1) &&
                           time >= capturedAtUtc.Subtract(TimeSpan.FromDays(1)).Subtract(TimeSpan.FromMinutes(10)))
            .GroupBy(GetIdentity, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(item => item.CreatedAtUtc).First())
            .OrderByDescending(item => item.CreatedAtUtc)
            .ThenByDescending(item => item.RecordId)
            .Take(SecurityEventProvider.MaximumEvents)
            .ToArray();

        var warnings = current.Warnings.Concat(subscriptionWarnings)
            .Where(warning => !string.IsNullOrWhiteSpace(warning))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return new SecurityEventSnapshot(1, capturedAtUtc.ToUniversalTime(), events, current.SourcesQueried, warnings.Take(64).ToArray());
    }

    private static string GetIdentity(SecurityEventObservation item) => item.RecordId is { } recordId
        ? $"{item.LogName}\0{recordId}"
        : $"{item.LogName}\0{item.Provider}\0{item.EventId}\0{item.CreatedAtUtc:O}";
}
