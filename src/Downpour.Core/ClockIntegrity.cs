namespace Downpour.Core;

public enum ClockVerdict { Consistent, BackwardJump, ForwardJump, MonotonicMismatch, Unknown }

public sealed record ClockEvidence(
    DateTimeOffset SystemUtc,
    DateTimeOffset? LastKnownUtc,
    TimeSpan? Uptime,
    DateTimeOffset? BootUtc);

public sealed record ClockFinding(ClockVerdict Verdict, string Detail);

/// <summary>
/// Checks that the wall clock agrees with what the machine itself says. Expiry, suppression lifetimes, evidence
/// freshness, feed publication age and audit ordering all trust the system clock; a backward jump can revive expired
/// evidence and reorder history. Uptime and boot time are monotonic, so a clock that moved while the machine did not
/// restart is detectable. This reports; it never corrects time or blocks work.
/// </summary>
public static class ClockIntegrity
{
    public static readonly TimeSpan BackwardTolerance = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan ForwardTolerance = TimeSpan.FromHours(48);
    // Boot time plus uptime should agree with the clock to within minutes; the wider forward tolerance above is for how
    // far a machine may legitimately have been off, not for how far its own uptime bookkeeping may disagree.
    public static readonly TimeSpan BootTolerance = TimeSpan.FromMinutes(15);

    public static ClockFinding Evaluate(ClockEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (evidence.LastKnownUtc is not { } last) return new(ClockVerdict.Unknown, "No previous reading is stored, so the clock cannot be compared yet.");
        var delta = evidence.SystemUtc - last;
        if (delta < -BackwardTolerance)
            return new(ClockVerdict.BackwardJump, $"The system clock moved back by {-delta.TotalMinutes:0} minutes since the last reading.");
        if (delta > ForwardTolerance && evidence.Uptime is null)
            return new(ClockVerdict.ForwardJump, $"The system clock jumped forward by {delta.TotalHours:0.0} hours without a known uptime.");
        if (evidence.BootUtc is { } boot && evidence.Uptime is { } uptime)
        {
            var expectedNow = boot + uptime;
            if ((expectedNow - evidence.SystemUtc).Duration() > BootTolerance)
                return new(ClockVerdict.MonotonicMismatch,
                    $"The clock reads {evidence.SystemUtc:O} but boot time plus uptime implies {expectedNow:O}; time may have been changed without a restart.");
            if (evidence.SystemUtc < boot)
                return new(ClockVerdict.MonotonicMismatch, "The clock reads earlier than the recorded boot time, which is impossible without a clock change.");
        }
        return new(ClockVerdict.Consistent, delta >= TimeSpan.Zero
            ? $"The clock advanced {delta.TotalMinutes:0} minutes since the last reading."
            : $"The clock moved back {-delta.TotalMinutes:0} minutes, inside the {BackwardTolerance.TotalMinutes:0}-minute tolerance.");
    }
}
