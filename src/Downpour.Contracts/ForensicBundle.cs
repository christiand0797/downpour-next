namespace Downpour.Contracts;

public sealed class ForensicChainOfCustody
{
    public string Hostname { get; init; } = "";
    public string OsDescription { get; init; } = "";
    public string OsArchitecture { get; init; } = "";
    public string CollectorVersion { get; init; } = "Downpour Next v0.1.15";
    public DateTimeOffset CollectedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string LocalIpAddresses { get; init; } = "";
    public string MacAddresses { get; init; } = "";
    public string EvidenceIntegritySha256 { get; set; } = "";
}

public sealed class ForensicArtifactItem
{
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string Severity { get; init; } = "INFORMATIONAL";
    public string? Technique { get; init; }
    public DateTimeOffset? TimestampUtc { get; init; }
    public string? RawEvidenceReference { get; init; }
}

public sealed class ForensicEvidenceBundle
{
    public int SchemaVersion { get; init; } = 1;
    public ForensicChainOfCustody ChainOfCustody { get; init; } = new();
    public int TotalEvidenceCount => Artifacts.Count;
    public IReadOnlyList<ForensicArtifactItem> Artifacts { get; init; } = [];
    public IReadOnlyList<string> AttackerIps { get; init; } = [];
    public IReadOnlyList<string> SuspiciousPersistenceItems { get; init; } = [];
    public IReadOnlyList<string> SecurityAlertIds { get; init; } = [];
    public string LegalDisclaimer { get; init; } =
        "This digital evidence bundle was collected using strictly read-only, non-destructive forensic observation. The integrity of the bundle is sealed using SHA-256 for chain of custody and suitable for submission to law enforcement (police report, FBI IC3 filing, or CERT).";
}
