namespace Downpour.Core;

public enum ReleaseTrustState { Verified, UnsignedDevelopment, Untrusted }

public sealed record ReleaseTrustDecision(ReleaseTrustState State, bool AllowsInstall, string Summary);

/// <summary>
/// Turns a manifest signature result into an install decision. A tampered or unreadable signature is refused even in
/// development builds, because "invalid" is evidence of interference rather than of a missing key. Unsigned builds are
/// only allowed when the caller states that the channel does not require signatures yet; once a release channel does,
/// the same bytes become untrusted and the installer must fail closed.
/// </summary>
public static class ReleaseTrustPolicy
{
    public static ReleaseTrustDecision Decide(ReleaseSignatureStatus status, bool requiresSignature)
    {
        if (status == ReleaseSignatureStatus.Invalid)
            return new(ReleaseTrustState.Untrusted, false, "The release signature is present but does not verify. Nothing will be installed.");
        if (status == ReleaseSignatureStatus.Valid)
            return new(ReleaseTrustState.Verified, true, "The release manifest matches its pinned signing key.");
        return requiresSignature
            ? new(ReleaseTrustState.Untrusted, false, "This channel requires a signed manifest and this build has none.")
            : new(ReleaseTrustState.UnsignedDevelopment, true, "Unsigned development build. Provenance cannot be verified; install only from a source you trust.");
    }
}
