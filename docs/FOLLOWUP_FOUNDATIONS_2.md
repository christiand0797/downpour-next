# Follow-up foundations, round two

Fifteen bounded, tested Core foundations for the next layer of work, landed after v0.1.25 and after the suppression
list. **None of these is wired into a route, service loop or the updater yet.** Each entry says what exists, what the
tests prove, and exactly what wiring would need to be true before it can be called working.

The rule from round one still applies: a foundation is not a feature, and this document never claims parity with a
commercial product.

| # | Foundation | What it does | Wired? | Wiring needs |
|---|---|---|---|---|
| 1 | `EventLogContinuity` | Per-channel cursor that only moves forward, plus a catch-up plan that distinguishes "current", "catch up N records" and "N records were already rolled out — that window cannot be recovered". | No | Persist a cursor per channel beside the alert DB; advance it only after a successful ingest; call `Plan` on service start and surface the lost-window note. |
| 2 | `EgressBaseline` | Per-process baseline of network owner + country (never addresses or payloads); reports only when an owner is new **and** the transfer is large. | No | A sampling loop over established TCP owners, an owner/ASN resolver, and a finding source. Currently no continuous sampler exists. |
| 3 | `ClockIntegrity` | Compares the wall clock with the last reading, uptime and boot time; names backward jumps, unexplained forward jumps and monotonic mismatch. | No | Store the last reading, pass uptime/boot time from the service, and decide which verdicts become notices versus findings. |
| 4 | `CrossViewInventory` | Generic diff between two independent enumerations (SCM vs registry services, modules vs driver keys, two TCP table APIs); calls differences consistency anomalies, never evidence of tampering. | No | A second enumeration path per artifact kind; a known-differences list (per-session services and similar legitimately differ). |
| 5 | `RuleCoverageMap` | Separates rules that cannot fire here (missing channel, missing field) from rules that are merely quiet, and only calls silence silent when the caller states a full observation window. | No | Channel/field inventories from the collectors plus per-rule fire counts; a panel that shows "cannot fire here" next to empty results. |
| 6 | `ExploitMitigationPosture` | Scores per-process CFG/ACG/CIG/non-Microsoft DLL blocking/DEP/ASLR, ranks high-value processes, and produces remedies that route into the existing fixer. | No | A read-only `Get-ProcessMitigation`-equivalent reader; the recommendation must reuse the current fixer path rather than adding a second one. |
| 7 | `FeedScheduling` | Respects a metered connection and a daily byte budget, defers bulk sources first, and never starves small freshness-critical sources; says which sources are deferred and why. | No | Metered state from Windows, actual per-source sizes, and a budget persisted per day. The catalog currently refreshes through its own loop. |
| 8 | `AlertReplayDiff` | Compares expected and actual alert sets from a recorded corpus: missing, unexpected and severity changes. | No | A sanitized corpus plus a replay runner in the gate script. This is the intended gate for any future rule or parser change. |
| 9 | `StoreRetentionAccounting` | Reports retained vs capacity, oldest evidence, per-day evictions and warns when capacity, not age, is removing evidence. | No | Eviction timestamps from the store's delete path; a line in "Persistence" or the alert footnote. |
| 10 | `DetectionExplanation` | Builds the "why this fired" text from rule id, fields used, missing evidence, boundary and confidence; bounded and content-free by construction. | No | Alert records that carry the field list and missing-evidence list; the UI panel. |
| 11 | `OnboardingPlan` | Computes the next setup step (feeds, baseline, permissions, quiet-period explanation) and keeps a genuine feed failure distinct from an expected quiet start. | No | Feed/baseline/permission state from the service; the first-run surface. |
| 12 | `UpdateStagingJournal` | Legal update transitions only (verified before staged, staged before applied), verification detail required, rollback recorded, and a recovery sentence per state. | No | The updater must adopt the journal; signature checks remain a separate gate, so this does not change trust. |
| 13 | `PortableSettingsBundle` | Passphrase-derived (PBKDF2 + AES-GCM) export/import for settings, suppressions and selected cases; feed credentials refused by default; tamper and wrong-passphrase failures are explicit. | No | An export/import surface, a passphrase prompt, and a decision on which case content may leave the machine. |
| 14 | `DomainConfusables` | Decodes IDN, detects mixed scripts, folds common Cyrillic/Greek/fullwidth confusables, and names protected-brand lookalikes while showing the decoded form. | No | A call site in DNS/connection analysis; a context-only presentation so a lookalike is never silently blocked. |
| 15 | `WeeklyDigest` | Builds a local Markdown summary: new autostarts, hidden matches, expired suppressions, blind sensors, review backlog, most active rule. | No | A weekly schedule, an output path the user chooses, and inputs assembled from existing stores. No email, no telemetry. |

## Test coverage added

`tests/Downpour.Tests/FollowUpDetectionTests.cs` and `FollowUpOperationsTests.cs` cover: cursor monotonicity and
channel isolation, catch-up versus lost windows, egress novelty/volume gating, clock verdicts, cross-view known
differences, rule capability versus silence, replay diff categories, lookalike domains, mitigation ranking, metered
budget scheduling, retention warnings, explanation bounds and provisional labelling, onboarding order, journal
transition refusals and recovery, bundle round-trip plus tamper/wrong-passphrase rejection, and digest content.

Build: Debug clean. Tests: 1,473 passed, 0 failed.

## Deliberately not built

Telemetry or intel sharing, more feeds, AV-style self-defense that fights the user's own tools, and any automatic
remediation behind these findings. Each adds risk or noise faster than it adds security.

## Why this order matters

The first three are the ones that change what the product can honestly claim: bookmarks decide whether a quiet period
is real, clock integrity decides whether old evidence is really old, and the explanation decides whether a person can
act on a finding instead of suppressing it.
