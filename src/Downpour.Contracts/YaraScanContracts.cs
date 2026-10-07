namespace Downpour.Contracts;

/// <summary>Load result for one bundled rule file. Files that fail to compile are listed, not hidden.</summary>
public sealed record YaraRuleFileStatus(string File, bool Loaded, int RuleCount, bool RelaxedSyntax, string? Error);

/// <summary><see cref="LowConfidence"/> marks rules that also match clean Windows system files (rule_quality.json); they never raise alerts.</summary>
public sealed record YaraRuleMatch(string Rule, string Namespace, string Severity, string Description, string Technique, IReadOnlyList<string> Tags, bool LowConfidence = false);

// ---- Helper process protocol (Downpour.Scanner.exe stdin/stdout, one JSON object per line) ----

/// <summary>First line the helper writes. <see cref="Fatal"/> is set when the engine could not start.</summary>
public sealed record ScannerReady(int SchemaVersion, string EngineVersion, int RuleCount, IReadOnlyList<YaraRuleFileStatus> RuleFiles, string? Fatal, int LowConfidenceRules = 0);

public sealed record ScannerFileRequest(long Id, string Path);

/// <summary>Status: matched, clean, skipped, timeout, error.</summary>
public sealed record ScannerFileResult(long Id, string Status, string? Message, long Size, IReadOnlyList<YaraRuleMatch> Matches);

// ---- Service pipe (Downpour.YaraScan.v1) ----

public static class YaraScanOperations
{
    public const string Status = "status";
    public const string Start = "start";
    public const string Cancel = "cancel";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Status, Start, Cancel };
}

public sealed record YaraScanRequest(int SchemaVersion, Guid RequestId, string Operation, string? Path = null, bool Recursive = false, bool SkipMicrosoftSigned = true);

public sealed record YaraScanFinding(string Path, long Size, IReadOnlyList<YaraRuleMatch> Matches);

/// <summary>State: idle, starting, running, completed, cancelled, failed.</summary>
public sealed record YaraScanJob(
    Guid JobId,
    string Root,
    bool Recursive,
    string State,
    int FilesQueued,
    int FilesScanned,
    int FilesSkipped,
    int FilesFailed,
    string? CurrentFile,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? FinishedAtUtc,
    string? Message,
    IReadOnlyList<YaraScanFinding> Findings,
    bool SkipMicrosoftSigned = true);

public sealed record YaraScanResponse(
    int SchemaVersion,
    Guid RequestId,
    bool Accepted,
    string ResultCode,
    string Message,
    bool EngineAvailable,
    string? EngineVersion,
    int RuleCount,
    IReadOnlyList<YaraRuleFileStatus>? RuleFiles,
    YaraScanJob? Job,
    int LowConfidenceRules = 0);
