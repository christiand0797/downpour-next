namespace Downpour.Contracts;

public sealed record CleanupCategory(
    string Key,
    string Label,
    string Description,
    long TotalBytes,
    int FileCount,
    string RiskLevel,
    string? OldestItemDate = null,
    string? LargestItemName = null,
    long? LargestItemBytes = null,
    IReadOnlyList<string>? TargetPaths = null);

public sealed record CleanupReport(
    int SchemaVersion,
    DateTimeOffset ScannedAtUtc,
    long TotalReclaimableBytes,
    int TotalReclaimableFiles,
    IReadOnlyList<CleanupCategory> Categories);
