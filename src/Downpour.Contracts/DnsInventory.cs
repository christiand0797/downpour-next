namespace Downpour.Contracts;

public sealed record DnsCacheEntry(
    string Domain,
    int RecordType,
    int RiskScore,
    bool IsDga,
    IReadOnlyList<string> Factors);

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
