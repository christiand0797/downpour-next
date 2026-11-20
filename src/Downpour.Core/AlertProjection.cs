using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// The identity one Windows event observation receives in the alert store. This lives in Core so the service upsert
/// and the offline replay corpus cannot drift: both compute the key from the same rules.
/// </summary>
public static class AlertProjection
{
    public static string DedupKey(SecurityEventObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.CreatedAtUtc is null)
            throw new ArgumentException("An observation needs an event time before it can be identified.", nameof(observation));

        if (observation.EventId == 4625)
        {
            var timestamp = observation.CreatedAtUtc.Value.ToUniversalTime();
            var bucket = timestamp.UtcDateTime.Ticks / TimeSpan.FromMinutes(5).Ticks;
            return $"burst\0{observation.LogName}\0{observation.EventId}\0{bucket}";
        }
        // Sysmon record IDs can restart after a log clear. Keep distinct event times distinct.
        if (observation.LogName.Equals(SysmonCatalog.LogName, StringComparison.OrdinalIgnoreCase) && observation.RecordId is { } sysmonRecord)
            return $"sysmon\0{observation.EventId}\0{sysmonRecord}\0{observation.CreatedAtUtc.Value.UtcTicks}";
        // High-volume informational events become one alert per event type per hour instead of one per record.
        if (observation.RecordId is not null && IsRollupEvent(observation.LogName, observation.EventId))
        {
            var hour = observation.CreatedAtUtc.Value.ToUniversalTime().ToString("yyyyMMddHH");
            return $"rollup\0{observation.LogName}\0{observation.EventId}\0{hour}";
        }
        if (observation.RecordId is { } recordId)
            return $"record\0{observation.LogName}\0{observation.EventId}\0{recordId}";
        var fallbackTime = observation.CreatedAtUtc.Value.ToUniversalTime().ToString("yyyyMMddHHmm");
        return $"fallback\0{observation.LogName}\0{observation.Provider}\0{observation.EventId}\0{fallbackTime}";
    }

    private static bool IsRollupEvent(string logName, int eventId) =>
        (logName.Equals("Microsoft-Windows-PowerShell/Operational", StringComparison.OrdinalIgnoreCase) && eventId == 4104) ||
        (logName.Equals("Security", StringComparison.OrdinalIgnoreCase) && eventId is 4688 or 4663 or 4672 or 4673);
}
