# Downpour Next 0.1.26

Unsigned portable Windows x64 build. No installer, no service registration, no code signing, no telemetry.

## What changed since 0.1.25

### Suppressions are visible and reversible

- Alerts now lists active false-positive suppressions with their confirmation count, how many matches each has hidden, and its expiry; expired rules are marked and stop hiding new matches.
- **Re-arm** on that list clears the rule, reopens its suppressed alerts and stops hiding future matches through the existing audited transition.
- Confirming a suppression now counts the alerts it actually hides, not just later ingestions.

### Detection continuity is now stated, not assumed

- Per-channel event-log cursors are stored only after a successful ingest and can never rewind.
- On start the service compares each cursor with the log's oldest surviving record; a rolled-out (or cleared) window becomes an Alerts warning instead of a silent gap.
- A cleared channel whose numbering restarts is re-baselined rather than leaving the cursor stuck.
- A backwards system-clock jump (more than five minutes) is reported, because expiry and suppression lifetimes trust that clock.

### Alert store honesty

- Pruning records evictions per day. The snapshot now carries retained/capacity/oldest/eviction counts, and capacity pressure that removes evidence before the retention window appears as a warning.
- The capacity warning only fires when the store is at least 90% full, so a small young store is not misreported.

### Explain a finding

- Clicking an alert opens a "why this fired" explanation: the rule, channel/provider/event, record, first/last seen, occurrence count, what evidence is unavailable, and the boundary that set the severity. It states plainly that no confidence score is inferred.

### Foundations added (not all wired)

Twenty-eight bounded, tested Core modules across two rounds cover event continuity, egress baselining, clock integrity, cross-view inventory diffing, rule coverage/silence, per-process mitigation posture, metered feed scheduling, replay diffing, retention accounting, detection explanations, onboarding, update staging, encrypted portable bundles, IDN confusables and a weekly digest. `docs/FOLLOWUP_FOUNDATIONS.md` and `docs/FOLLOWUP_FOUNDATIONS_2.md` state which are wired and what each one still needs.

## Verification

- `dotnet build Downpour.slnx -c Release` and full Release test suite: **1,477 passed, 0 failed**.
- Portable package: 1,077 entries, 736 MB expanded.
- Packaged route smoke: every route started with telemetry from its owned service, graceful close stopped the owned service, YARA helper loaded 179 rules and scanned a benign fixture without matches.
- Window smoke: native startup, maximize/restore, resize and owned-service shutdown passed.
- ZIP SHA-256 `56d35d7bed95dbcd2f56878627bffc54f39fc699d6e619328e4e09ddc5f64f0a`.
- SBOM SHA-256 `aaea9757023f2888709b121bc084c8b40ca7dd99bf9c596c51f95450cf131e11`.

## Not done / limits

- The new Alerts explanation panel was compiled and shipped but not visually inspected; the route smoke does not click it.
- Egress byte-volume baselining cannot be wired without an ETW collector (or admin-only ESTATS); connection ownership alone is available without admin. Recorded as blocked.
- The build is unsigned. Signature enforcement remains disabled until offline signing keys exist.
- No ARM64 package: it needs an arm64 YARA-X module or a managed fallback.
- Several foundations remain unreferenced by any route; the docs say so rather than implying coverage.
