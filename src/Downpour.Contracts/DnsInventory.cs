namespace Downpour.Contracts;

/// <summary>
/// Context for a cached name whose decoded form differs from its ASCII form or resembles a protected brand. It is shown
/// beside the original name and never changes a block, scan or quarantine decision.
/// </summary>
public sealed record DomainLookalike(
    string DecodedName,
    string Scripts,
    bool MixedScript,
    IReadOnlyList<string> Brands,
    string Verdict);

public sealed record DnsCacheEntry(
    string Domain,
    int RecordType,
    int RiskScore,
    bool IsDga,
    IReadOnlyList<string> Factors,
    DomainLookalike? Lookalike = null);

public sealed record DnsFinding(
    string Severity,
    string Technique,
    string Summary,
    string Indicator);

public sealed record DnsCacheSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    int TotalEntries,
    int HighRiskCount,
    int MediumRiskCount,
    IReadOnlyList<DnsCacheEntry> Entries,
    IReadOnlyList<DnsFinding> Findings,
    IReadOnlyList<string> Warnings);

public sealed record EmailSecurityCheckResult(
    string Domain,
    string SpfStatus,
    string SpfVerdict,
    string SpfRecord,
    string DmarcStatus,
    string DmarcVerdict,
    string DmarcRecord,
    string DkimStatus,
    string DkimVerdict,
    string DkimSelector);
