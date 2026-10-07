using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Projects only catalog-approved, metadata-only Sysmon review observations into the alert path.</summary>
internal static class SysmonAlertBatch
{
    internal static SecurityEventSnapshot Create(IEnumerable<SysmonObservation> events, DateTimeOffset capturedAtUtc)
    {
        var keys = new HashSet<long>();
        var observations = new List<SecurityEventObservation>();
        foreach (var item in events.Take(SysmonProvider.MaximumEvents))
        {
            if (!SysmonCatalog.TryGetAlertRule(item.LogName, item.EventId, out var rule) ||
                !string.Equals(item.Provider, SysmonCatalog.ProviderName, StringComparison.OrdinalIgnoreCase) ||
                item.RecordId is not >= 0 || item.CreatedAtUtc is not { Offset.Ticks: 0 } time ||
                time > capturedAtUtc.AddMinutes(1) || time < capturedAtUtc.AddDays(-1).AddMinutes(-10) ||
                !keys.Add(item.RecordId.Value)) continue;
            observations.Add(new(SysmonCatalog.LogName, SysmonCatalog.ProviderName, item.EventId, item.RecordId,
                time, rule.Severity, rule.Technique, rule.Summary));
        }
        return new(1, capturedAtUtc, observations, 1, []);
    }
}
