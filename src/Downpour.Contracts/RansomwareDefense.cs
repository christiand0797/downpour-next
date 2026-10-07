namespace Downpour.Contracts;

public sealed record RansomwareProtectedDirectory(
    string Path,
    string DisplayName,
    int FileCount,
    long TotalBytes,
    double AverageEntropy,
    bool IsAccessible);

public sealed record RansomwareCanaryStatus(
    string FileName,
    string DirectoryPath,
    bool Exists,
    bool IntegrityVerified,
    double CurrentEntropy,
    string Status);

public sealed record RansomwareThreatIndicator(
    string Category,
    string Description,
    string TargetPath,
    string Severity,
    DateTimeOffset DetectedAtUtc);

public sealed record VolumeShadowCopyPosture(
    string VssServiceStatus,
    bool HasRecentVssTampering,
    IReadOnlyList<string> TamperingEvidence);

public sealed record RansomwareDefensePosture(
    IReadOnlyList<RansomwareProtectedDirectory> ProtectedDirectories,
    IReadOnlyList<RansomwareCanaryStatus> Canaries,
    IReadOnlyList<RansomwareThreatIndicator> ThreatIndicators,
    VolumeShadowCopyPosture VssPosture,
    int TotalFilesMonitored,
    long TotalBytesMonitored,
    string OverallStatus,
    DateTimeOffset InspectedAtUtc,
    string SecurityNotice);
