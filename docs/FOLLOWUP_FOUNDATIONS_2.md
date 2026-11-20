# Follow-up foundations, round two

Fifteen bounded, tested Core foundations for the next layer of work, landed after v0.1.25 and after the suppression
list. Two are now wired (event-log cursors in the service loop and retention eviction accounting in the alert store); the
other thirteen are **not** wired into a route, service loop or the updater. Each entry says what exists, what the
tests prove, and exactly what wiring would need to be true before it can be called working.

The rule from round one still applies: a foundation is not a feature, and this document never claims parity with a
commercial product.

| # | Foundation | What it does | Wired? | Wiring needs |
|---|---|---|---|---|
| 1 | `EventLogContinuity` | Per-channel cursor that only moves forward, plus a catch-up plan that distinguishes "current", "catch up N records" and "N records were already rolled out — that window cannot be recovered". | **Yes** | `event_cursors` table holds one monotonic row per channel, saved only after a successful ingest; the service passes prior cursors into the capture, and a lost window becomes an Alerts warning from `Plan`. A channel whose record numbering restarts (a cleared log) is detected by a lower newest id, its cursor is deleted, and the next capture re-baselines instead of staying stuck high. Ingestion itself is still the 24-hour lookback, so this reports the gap rather than replaying records from a cursor. Microsoft does not document record numbering after a clear, which is why the reset is treated as a discontinuity rather than as loss. |
| 2 | `EgressBaseline` | Per-process baseline of network owner + country (never addresses or payloads); reports only when an owner is new **and** the transfer is large. | No — blocked | Ownership and PID are available without admin through `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)`, but byte volume is not in those tables: it needs an ETW consumer for Microsoft-Windows-Kernel-Network, or ESTATS, whose enabling call requires Administrators. A non-elevated service can therefore not wire the volume half honestly. |
| 3 | `ClockIntegrity` | Compares the wall clock with the last reading, uptime and boot time; names backward jumps, unexplained forward jumps and monotonic mismatch. | **Partly** | The service stores its last reading in `service_clock` (every 5 minutes, loaded on start) and turns a backward jump into an Alerts warning. The boot-time cross-check stays unused because uptime is derived from the same clock, so it could not prove tampering; that needs an independent boot source. |
| 4 | `CrossViewInventory` | Generic diff between two independent enumerations (SCM vs registry services, modules vs driver keys, two TCP table APIs); calls differences consistency anomalies, never evidence of tampering. | **Partly** | The services inventory now compares the SCM enumeration with the `Services` registry key and adds a bounded warning naming up to three one-sided entries when 1–10 differ. On the development machine both views agreed, so the warning stayed absent. The driver inventory also compares every running driver service (the WMI fallback used when kernel bases are hidden) with the `Services` registry keys and warns when 1–10 running services have no key; it was quiet on the development machine with 182 running services. Port views remain unwired. |
| 5 | `RuleCoverageMap` | Separates rules that cannot fire here (missing channel, missing field) from rules that are merely quiet, and only calls silence silent when the caller states a full observation window. | No | Channel/field inventories from the collectors plus per-rule fire counts; a panel that shows "cannot fire here" next to empty results. |
| 6 | `ExploitMitigationPosture` | Scores per-process CFG/ACG/CIG/non-Microsoft DLL blocking/DEP/ASLR, ranks high-value processes, and produces remedies that route into the existing fixer. | **Yes** | `ProcessMitigationProvider` reads the six policies with `GetProcessMitigationPolicy`, keeps one row per image name (worst instance) and counts refusals; Hardening shows the six most exposed images. DEP needs full query rights, so only complete readings are reported. Remediation remains guidance text, not an applied fixer action. |
| 7 | `FeedScheduling` | Respects a metered connection and a daily byte budget, defers bulk sources first, and never starves small freshness-critical sources; says which sources are deferred and why. | No — uncertain | Per-source sizes and a per-day budget are straightforward, but the metered signal is not: `Windows.Networking.Connectivity` is not documented as reliable from a session-0 service, and Network List Manager `INetworkCostManager` documents no server/session-0 support. Needs a runtime experiment on the target service identity before it can be claimed, plus the actual refresh loop integration. |
| 8 | `AlertReplayDiff` | Compares expected and actual alert sets from a recorded corpus: missing, unexpected and severity changes. | No | A sanitized corpus plus a replay runner in the gate script. This is the intended gate for any future rule or parser change. |
| 9 | `StoreRetentionAccounting` | Reports retained vs capacity, oldest evidence, per-day evictions and warns when capacity, not age, is removing evidence. | **Yes** | `PruneAsync` records evictions in `alert_evictions`; every snapshot carries an `AlertRetentionSummary`, and its warnings appear in the Alerts warning panel. The summary is not yet plotted on the Persistence page. |
| 10 | `DetectionExplanation` | Builds the "why this fired" text from rule id, fields used, missing evidence, boundary and confidence; bounded and content-free by construction. | **Partly** | A second, catalog-specific builder (`AlertExplanation.ForAlert`) explains any stored alert from metadata already present, without inventing a confidence score; clicking an Alerts row opens that text. `DetectionExplanation` itself is still unused because alerts do not yet carry their field/missing-evidence lists. |
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

Build: Debug clean. Tests: 1,479 passed, 0 failed. An independent documentation check confirmed `OldestRecordNumber` is the oldest record still present (so the rollover gap check is valid) and that record numbering after a channel clear is undocumented, prompting the reset handling above. The service starts and refreshes (6 of 7 channels on a non-elevated account, as expected), with no exception in the event-monitor path.

A real bug surfaced during wiring: `StoreRetentionAccounting` warned that a small, young store was evicting by capacity. Capacity warnings now require the store to be at least 90% full.

## Deliberately not built

Telemetry or intel sharing, more feeds, AV-style self-defense that fights the user's own tools, and any automatic
remediation behind these findings. Each adds risk or noise faster than it adds security.

## Why this order matters

The first three are the ones that change what the product can honestly claim: bookmarks decide whether a quiet period
is real, clock integrity decides whether old evidence is really old, and the explanation decides whether a person can
act on a finding instead of suppressing it.
