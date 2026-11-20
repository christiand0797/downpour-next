namespace Downpour.Core;

public sealed record ContentViolation(string RelativePath, string Problem);

/// <summary>
/// Compares a directory of trust inputs (Sigma rules, the feed catalog, threat packs) with a pinned SHA-256 map. Unlike
/// installation integrity, an unexpected file is a violation here: a dropped rule file can change detection behaviour
/// without modifying anything the manifest covers, and an attacker who can write rules can make a rule never match.
/// </summary>
public static class TrustedContentIntegrity
{
    public static IReadOnlyList<ContentViolation> Verify(
        IReadOnlyDictionary<string, string> expectedSha256,
        IReadOnlyDictionary<string, string> actualSha256)
    {
        ArgumentNullException.ThrowIfNull(expectedSha256);
        ArgumentNullException.ThrowIfNull(actualSha256);
        var violations = new List<ContentViolation>();
        foreach (var (relative, expected) in expectedSha256)
        {
            if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) ||
                relative.Contains("..", StringComparison.Ordinal) || relative.Contains(':'))
            {
                violations.Add(new(relative, "The pinned path is unsafe."));
                continue;
            }
            if (!actualSha256.TryGetValue(relative, out var actual))
            {
                violations.Add(new(relative, "The pinned file is missing."));
                continue;
            }
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                violations.Add(new(relative, "The file does not match its pinned hash."));
        }
        foreach (var relative in actualSha256.Keys.Where(path => !expectedSha256.ContainsKey(path)))
            violations.Add(new(relative, "An unexpected file would be loaded as a trust input."));
        return violations.OrderBy(violation => violation.RelativePath, StringComparer.OrdinalIgnoreCase).ToArray();
    }
}

/// <summary>A small record of the audit chain head, kept somewhere the audited account cannot rewrite.</summary>
public sealed record AuditAnchor(DateTimeOffset RecordedUtc, string ChainHead, int EntryCount);

/// <summary>
/// Detects tampering with the local hash-chained audit log from an anchor the user keeps elsewhere (a USB stick, a
/// synced folder). The chain alone cannot prove anything against same-user malware that knows the DPAPI key, but a
/// shorter chain or a different head at the same length is positive evidence of truncation or rewriting.
/// </summary>
public static class AuditAnchorPolicy
{
    public static string? VerifyContinuity(AuditAnchor? lastKnown, string currentHead, int currentEntryCount)
    {
        ArgumentNullException.ThrowIfNull(currentHead);
        if (currentEntryCount < 0) throw new ArgumentOutOfRangeException(nameof(currentEntryCount));
        if (lastKnown is null) return null; // Trust on first use; the anchor is created by the operator's export.
        if (currentEntryCount < lastKnown.EntryCount)
            return $"The audit log holds {currentEntryCount:N0} entries but the external anchor recorded {lastKnown.EntryCount:N0}. The log was truncated.";
        if (currentEntryCount == lastKnown.EntryCount && !string.Equals(currentHead, lastKnown.ChainHead, StringComparison.OrdinalIgnoreCase))
            return "The audit log has the same length as the external anchor but a different chain head. Entries were rewritten.";
        return null;
    }

    public static AuditAnchor CreateAnchor(DateTimeOffset now, string chainHead, int entryCount)
    {
        ArgumentNullException.ThrowIfNull(chainHead);
        if (entryCount < 0) throw new ArgumentOutOfRangeException(nameof(entryCount));
        return new AuditAnchor(now, chainHead, entryCount);
    }
}
