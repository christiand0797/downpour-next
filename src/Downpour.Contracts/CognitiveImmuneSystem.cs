namespace Downpour.Contracts;

/// <summary>Schema-v1 measured local review. Counts describe the returned alert window, not total protection.</summary>
public sealed record CisAssessment(
    int SchemaVersion, DateTimeOffset CapturedAtUtc, string Status,
    DateTimeOffset? AlertCapturedAtUtc, int? StoredAlerts, int? ReviewedAlerts,
    int? OpenAlerts, int? UrgentOpenAlerts, int? VerifiedActiveAlerts, int? SuppressedAlerts,
    int? ObservedTechniques, IReadOnlyList<CisSourceMeasurement> Sources,
    IReadOnlyList<SecurityAlert> RecentAlerts, IReadOnlyList<CisCorrelationMeasurement> Correlations,
    IReadOnlyList<string> Warnings);

public sealed record CisSourceMeasurement(string Name, string Status, string Detail);
public sealed record CisCorrelationMeasurement(string Title, string EvidenceSummary, string Limitation);

/// <summary>Checks consistency with an unsigned local release manifest. It is not publisher authentication.</summary>
public sealed record PackageIntegrityAssessment(
    int SchemaVersion, DateTimeOffset CapturedAtUtc, string Status, string? Version,
    string? SourceCommit, string? ManifestSha256, int ExpectedFiles, int CheckedFiles,
    int MatchingFiles, long BytesHashed, IReadOnlyList<PackageIntegrityFinding> Findings,
    string Scope);

public sealed record PackageIntegrityFinding(string RelativePath, string Status);
