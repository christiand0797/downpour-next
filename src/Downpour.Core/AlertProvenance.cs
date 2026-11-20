namespace Downpour.Core;

/// <summary>
/// Where a persisted alert's evidence came from. Central alerts written by earlier service sessions have no provenance;
/// this record lets new alerts carry it so expiry and key revocation can be re-evaluated later without guessing which
/// source produced an indicator.
/// </summary>
public sealed record AlertProvenance(
    string? SourceId,
    string? SourceVersion,
    DateTimeOffset? RetrievedUtc,
    string? Indicator,
    string? IndicatorKind);

public enum EvidenceFreshness { Current, Stale, Unknown }

public static class AlertProvenancePolicy
{
    public static AlertProvenance Unknown { get; } = new(null, null, null, null, null);

    public static bool IsComplete(AlertProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        return !string.IsNullOrWhiteSpace(provenance.SourceId) && provenance.RetrievedUtc is not null;
    }

    /// <summary>
    /// Classifies stored evidence against a maximum age. Missing provenance is <see cref="EvidenceFreshness.Unknown"/>
    /// rather than "current": an alert from an older build must not inherit trust it never recorded.
    /// </summary>
    public static EvidenceFreshness Classify(AlertProvenance provenance, DateTimeOffset now, TimeSpan maximumAge)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        if (maximumAge <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maximumAge));
        if (!IsComplete(provenance) || provenance.RetrievedUtc is not { } retrieved) return EvidenceFreshness.Unknown;
        if (retrieved > now + TimeSpan.FromMinutes(5)) return EvidenceFreshness.Unknown;
        return now - retrieved > maximumAge ? EvidenceFreshness.Stale : EvidenceFreshness.Current;
    }

    public static string Describe(EvidenceFreshness freshness, AlertProvenance provenance) => freshness switch
    {
        EvidenceFreshness.Current => $"Current evidence from source {provenance.SourceId} retrieved {provenance.RetrievedUtc:yyyy-MM-dd HH:mm} UTC.",
        EvidenceFreshness.Stale => $"Historical observation. Source {provenance.SourceId} evidence is older than its allowed age.",
        _ => "Source provenance was not recorded, so this alert cannot be re-evaluated against a current source.",
    };
}
