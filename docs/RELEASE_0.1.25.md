# Downpour Next 0.1.25 — Visible trust work and honest blind spots

0.1.25 turns the untested gaps from 0.1.24 into either working behaviour or an explicitly stated limitation. Nothing
here changes the read-only default: detections still only inform, and every response action still needs your
confirmation.

## What you will notice

- **Alerts groups repeated findings.** Rows that share a source and subject collapse into one line with severity, count
  and time span, and a Filter button narrows the list to that exact finding. Individual triage state is untouched.
- **Investigation shows an evidence graph.** Opening a correlation finding draws the case: the finding, its evidence
  and related alerts, the techniques, providers and indicators those alerts name. It is built from the snapshot
  already loaded, is bounded, and is never persisted.
- **Persistence review reports changes since the previous scan.** Added and removed autostart, scheduled-task and
  driver entries are ranked, which the service baseline cannot do on its own because it only records additions and
  modifications.
- **False-positive suppressions now expire.** A suppression lapses after 90 days and stops hiding new matches; every
  match it hid is counted, re-arming clears the count, and the Alerts page reports active and expired suppressions as
  notices instead of calling them a storage outage.
- **ThreatFox, URLhaus and MalwareBazaar come back with a key.** They still need a free abuse.ch Auth-Key, but saving
  one in Settings activates them, sends the `Auth-Key` header, and wakes the feed sweep immediately. Without a key
  they are never requested and the snapshot says why. PhishTank stays retired: no key fixes its expiring redirect.

## Foundations that are not features yet

Fifteen follow-ups were started as tested Core building blocks and are documented in `docs/FOLLOWUP_FOUNDATIONS.md`:
release trust policy with an offline signing script, per-source detection value, scoped suppressions, SBOM advisory
matching, rule/catalog integrity with an external audit anchor, a durable change ledger, alert provenance, a redacted
diagnostics bundle, blind-spot ranking, operator metrics, per-architecture scanner honesty, least-privilege ACL policy,
a read-only rescue kit plan, refresh budgets, and verifiable case packs. **None of them is wired into a route, the
updater or the service yet**, and this release does not claim otherwise.

## Verification for this build

- Debug build clean; the full suite passes (1,455 tests, including new regressions for expiry, hidden-match counting,
  component advisories, ACL policy, diagnostics redaction, case-pack signing and the suppression lifecycle).
- The package is built from the tagged commit: five self-contained executables report the same version and commit, the
  window smoke exercises native startup, resize, restore and owned-service shutdown, and the packaged smoke runs every
  route with the YARA helper and service pipes.
- The archive is verified entry-by-entry against its own manifest, and the GitHub assets are compared with the local
  hashes after upload.

## Still open

- Binaries and updater metadata remain unsigned. The signature verifier, trust policy and signing script exist; key
  custody does not, so the updater still trusts hashes from the same host.
- ARM64 has no package and no arm64 YARA-X module; the scanner capability rule states that honestly rather than
  pretending to scan.
- Per-subject suppression scope, a renewal action and a dedicated suppression list with per-rule counts remain.
- Acknowledgement timestamps are not stored, so operator metrics cannot yet show a real time-to-acknowledge.
- Hosted GitHub Actions is billing-blocked; the self-hosted gate workflow is dispatch-only until a runner is registered.

See `docs/RELEASE_TRUST.md`, `docs/FOLLOWUP_FOUNDATIONS.md`, `SHARED_CONTEXT.md` and `TODO.md`.
