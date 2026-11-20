# Release trust model

Downpour Next ships unsigned portable builds today. The updater verifies downloaded archives against hashes
published alongside the release, but those hashes come from the same host as the binaries. A compromised GitHub
account, token or release can therefore replace both. This document records the target model and the parts that
now exist in code.

## Target model

1. **Signed manifest.** `release-manifest.json` (already generated, one SHA-256 per file) is signed offline with an
   RSA-3072 or better key. The private key is never on the build machine or in CI.
2. **Pinned public key.** The desktop and update helper embed the public key. The key is never fetched at runtime,
   so a hostile host cannot substitute its own key.
3. **Fail closed when required.** A build configured for signed releases must refuse a manifest whose signature is
   missing or invalid. Unsigned development builds remain possible but are visibly "unsigned" in the UI.
4. **Reproducible build.** Two clean builds from the same commit produce byte-identical assemblies (modulo the
   signature), with deterministic paths and no timestamps. `release-manifest.json` can then be compared, not trusted.
5. **Provenance.** The release publishes the commit, SDK version, YARA-X digest and an in-toto/SLSA-style
   attestation, so a third party can rebuild and compare.
6. **Rollback protection.** The updater refuses a version older than the installed one (already enforced) and keeps
   the previous install until the new one starts successfully.

## Implemented in this slice

- `ReleaseSignatureVerifier` (`src/Downpour.Core/ReleaseIntegrity.cs`) verifies a detached RSA/SHA-256 signature over
  manifest bytes with a caller-supplied public key, and distinguishes `Unsigned`, `Valid` and `Invalid`.
- `InstallationIntegrity` verifies installed files against a manifest hash map, with path-traversal rejection, so a
  hostile manifest cannot probe outside the install root.
- Tests cover a valid signature, tampering, malformed input, a missing key and unsafe paths.

## Not yet implemented

- Key generation, custody and rotation; the private key must live offline.
- Signing the produced manifest in `v0.1.23-package.ps1` and shipping `release-manifest.json.sig`.
- Wiring verification into `PortableUpdateInstaller` and the desktop's own startup check. This must land together
  with a signed release; enabling it before a key exists would make every update fail.
- Reproducible build flags and a two-build comparison script.
- UI state for "signed by …" versus "unsigned development build".
