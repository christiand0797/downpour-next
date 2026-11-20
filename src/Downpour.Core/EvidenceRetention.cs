namespace Downpour.Core;

public enum EvidenceCategory { Alert, Audit, Export }

public sealed record EvidenceRetentionPolicy(int AlertDays, int AuditDays, int ExportDays)
{
    public static EvidenceRetentionPolicy Default { get; } = new(90, 180, 30);

    public int DaysFor(EvidenceCategory category) => category switch
    {
        EvidenceCategory.Alert => AlertDays,
        EvidenceCategory.Audit => AuditDays,
        _ => ExportDays,
    };

    public bool IsValid =>
        AlertDays is >= 1 and <= 3650 && AuditDays is >= 1 and <= 3650 && ExportDays is >= 1 and <= 3650;
}

/// <summary>
/// Age rules for locally stored evidence. Retention is evaluated by the owner of each store before a sweep, so a
/// policy change never deletes data as a side effect of reading it. Kept separate from the stores themselves so the
/// same policy applies to alerts, audit records and exported case files.
/// </summary>
public static class EvidenceRetention
{
    public static bool IsExpired(DateTimeOffset recordedAtUtc, EvidenceCategory category, EvidenceRetentionPolicy policy, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!policy.IsValid) throw new ArgumentOutOfRangeException(nameof(policy), "The retention policy is outside its bounds.");
        if (recordedAtUtc > nowUtc) return false;
        return nowUtc - recordedAtUtc > TimeSpan.FromDays(policy.DaysFor(category));
    }

    public static IReadOnlyList<string> ExpiredKeys(
        IEnumerable<(string Key, DateTimeOffset RecordedAtUtc, EvidenceCategory Category)> records,
        EvidenceRetentionPolicy policy,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(records);
        return records.Where(record => IsExpired(record.RecordedAtUtc, record.Category, policy, nowUtc))
            .Select(record => record.Key)
            .ToArray();
    }
}
