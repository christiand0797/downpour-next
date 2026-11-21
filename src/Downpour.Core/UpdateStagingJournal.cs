namespace Downpour.Core;

public enum UpdateState { Downloaded, Verified, Staged, Applied, RolledBack }

public sealed record UpdateRecord(string Version, UpdateState State, DateTimeOffset AtUtc, string Detail);

/// <summary>
/// Journal for a self-update so a crash mid-way is recoverable and never leaves a half-installed build. The legal
/// transitions are explicit: a package must be verified before staging, staged before it can be applied, and a failed
/// apply is recorded as a rollback rather than retried from an unknown state. Signature checks remain a separate gate.
/// </summary>
public static class UpdateStagingJournal
{
    private static readonly Dictionary<UpdateState, UpdateState[]> Allowed = new()
    {
        [UpdateState.Downloaded] = [UpdateState.Verified, UpdateState.RolledBack],
        [UpdateState.Verified] = [UpdateState.Staged, UpdateState.RolledBack],
        [UpdateState.Staged] = [UpdateState.Applied, UpdateState.RolledBack],
        [UpdateState.Applied] = [],
        [UpdateState.RolledBack] = [UpdateState.Downloaded],
    };

    public static UpdateRecord Advance(UpdateRecord record, UpdateState next, DateTimeOffset now, string detail = "")
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!Allowed.TryGetValue(record.State, out var allowed) || !allowed.Contains(next))
            throw new InvalidOperationException($"An update cannot move from {record.State} to {next}.");
        if (next == UpdateState.Verified && string.IsNullOrWhiteSpace(detail))
            throw new ArgumentException("Verification must record what was verified.", nameof(detail));
        return new UpdateRecord(record.Version, next, now, detail.Trim());
    }

    /// <summary>What to do with a journal entry found on start, including one interrupted mid-transition.</summary>
    public static string Recover(UpdateRecord? record) => record?.State switch
    {
        null => "No update is in progress.",
        UpdateState.Downloaded => "A downloaded package was never verified; discard it and download again.",
        UpdateState.Verified => "A verified package was not staged; discard it and download again rather than staging an older file.",
        UpdateState.Staged => "A package was staged but not applied; it is safe to apply after a fresh signature check.",
        UpdateState.Applied => "An update was applied; confirm the running version matches before trusting the record.",
        UpdateState.RolledBack => "The last update was rolled back; the previous build is the one running.",
        _ => "Unrecognized update state.",
    };

    public static int CountRollbacks(IEnumerable<UpdateRecord> journal) =>
        journal.Count(record => record.State == UpdateState.RolledBack);
}
