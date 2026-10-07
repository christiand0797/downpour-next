namespace Downpour.Contracts;

public sealed record SandboxFileMetrics(
    string FilePath,
    string FileName,
    long FileSizeBytes,
    string Sha256,
    string Sha1,
    string Md5,
    double ShannonEntropy,
    bool IsHighEntropy,
    DateTimeOffset AnalyzedAtUtc);

public sealed record SandboxPeDetails(
    bool IsPortableExecutable,
    string Architecture,
    int SectionCount,
    int WritableExecutableSectionCount,
    DateTimeOffset? TimestampUtc,
    bool HasAuthenticodeCertificate,
    IReadOnlyList<string> SuspiciousSectionNames);

public sealed record SandboxTriggeredIndicator(
    string Category,
    string Indicator,
    string Description,
    int Weight);

public sealed record SandboxReport(
    SandboxFileMetrics Metrics,
    SandboxPeDetails PeDetails,
    IReadOnlyList<SandboxTriggeredIndicator> TriggeredIndicators,
    int RiskScore,
    string Verdict,
    IReadOnlyList<string> RiskReasons,
    string SecurityNotice);
