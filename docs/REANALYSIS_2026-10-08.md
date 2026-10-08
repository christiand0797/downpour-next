# Repository reanalysis — 2026-10-08

The owner requested another whole-repository review after other agents' improvements. Baseline: `e933f0b`; latest published release at review start: v0.1.18 (`74ae152`). This supersedes the older 472-file inventory and the assumption that the parental/database/theme work is still unimplemented.

## Scope and evidence

`FILE_INVENTORY_2026-10-08.json` inventories all 530 tracked files by relative path, SHA-256, size and text line count: 358 C# files, 44 XAML files, seven projects, 33 YARA rules, 34 Markdown documents, and remaining assets/configuration. All tracked JSON and XML/XAML/project files parsed successfully. This is a captured working-tree inventory against the stated HEAD, including concurrent edits; hashes describe that snapshot and will change as work continues. Pattern signals identify native calls, launch sites, catch-all handlers, simulation/test injection points and desktop disk I/O for review; they are not proof of defects or a claim of line-by-line security certification. Ignored build outputs, local caches, telemetry, credentials and quarantine contents are excluded.

Current source inventory has 129 legacy entries: 21 in progress, 73 planned, 32 orphaned, and one each legacy/reference/declined. These conservative dispositions are retained. The read-only v29 review included parental_controls.py (configuration, SQLite history, hosts filtering, app enforcement, usage loop) and threat_hunt_engine.py (static BYOVD names) plus threat_feed_aggregator.py (bounded transport, parsing, cache/refresh). Native v2 data paths and acceptance tests, not old feature names or route counts, determine completion.

Initial current working-tree Debug build: zero warnings/errors; all 1,065 tests passed. That suite includes four new WatchTimeline draft tests, so clean release counts must be reported separately.

## Reconciled implementation

| Area | Current evidence | Remaining work |
|---|---|---|
| Parental Controls | Initialization callback crash repaired and incorporated by another agent; config/collection off dispatcher; atomic validated saves; real hosts/process review; simulated usage removed; save-picker export | Consented screen-time measurement, scoped enforcement broker, category provenance and coverage; narrow layout/manual acceptance |
| Threat databases | 19 fixed-host feeds, strict parsers, bounded downloads/cache, local connection/DNS/file matching, offline IP origin | License/availability/freshness maintenance, per-source false-positive evaluation, backend resilience and live UI failure states (active agent drafts) |
| Driver intelligence | LOLDrivers sample hashes plus signature-aware assessment, separate Driver Store inventory | Strong installed-service identity and signed, recoverable privileged driver workflows |
| Monitoring | Audio Shield, Anti-Stalker, case-file evidence, service-install grading, per-PC Threat Pulse baseline | Consent/retention review for each new sensor, watch timeline integration (active draft), clean-machine acceptance |
| UI | Shared HUD tokens, ring gauges, area fills, rain, Sakura/Kuro overlay already implemented | Narrow/high-DPI/focus/high-contrast acceptance across routes; remaining shared visual kit work |
| Integrity | HMAC-chained audit with DPAPI key and anchor; parser fuzzing | Separate identity/off-box anchoring, signed releases, adversarial process boundary testing |
| Response | Typed preview/consent/audit brokers, scheduled isolation release | Recovery defect repaired below; privileged COM calls still need installed/elevated boundary and bounded out-of-process execution acceptance |

## Concrete recovery defect and repair

HostIsolationExecutor swallowed firewall-removal failures, cancelled its scheduled release, and marked the host released. The IPC handler additionally forced `IsIsolated=false` for every release outcome. Partial setup rollback had the same cancellation problem, and SaveState swallowed write failures.

The repair retains the scheduled task and active state on incomplete or unverifiable removal; attempts all four exact current/legacy isolation rule names; verifies absence; surfaces actual executor state in both setup and release replies; records failed cleanup; retries timer cleanup; persists recovery intent before adding firewall rules; rejects a second isolation while the first is active; and makes scheduled release return a failure exit status for Task Scheduler retries. Release success says only that Downpour isolation rules are absent, not that all connectivity is restored. Three scheduled retries use Microsoft's [RestartInterval/RestartCount contract](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-restartinterval).

Regression coverage: 18 isolation tests pass, including failed removal, silent non-removal, failed verification, partial setup with successful/failed rollback, unavailable durable storage, re-isolation, startup expiry failure, audit evidence, and broker state propagation. New-isolation settings may be disabled without blocking consented release. Full current working-tree Debug checks now pass 1,076 tests. These tests use an injected firewall backend and do not isolate the development PC. Native elevated failure/reboot testing is still required. Portable scheduled recovery also depends on the executable remaining at its registered path; this is not an absolute recovery guarantee.

## Research and feature decisions

- [LOLDrivers API](https://www.loldrivers.io/api/) provides sample hashes and vulnerable/malicious categories. Its [repository license](https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/LICENSE) is Apache-2.0. Missing HVCI evidence remains unknown; driver name or valid signature alone is not a safety verdict. The existing v2 hash integration is a material improvement over v29's static name list.
- [URLhaus](https://urlhaus.abuse.ch/api/) and [ThreatFox](https://threatfox.abuse.ch/api/) API access has authentication/fair-use conditions. ThreatFox expires API indicators older than six months to reduce false positives. Availability of separate public exports must be checked independently of API authentication. Preserve provider errors and source timestamps; an empty/failed refresh must not imply a clean machine.
- Public dark-web threat research used [CISA's ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide) and [Play ransomware advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a). Candidate follow-ups are explicit-consent breach monitoring, attributed ransomware indicators, and recovery readiness checks. No direct onion-service crawl, stolen-data collection, or hidden-web coverage is claimed.
- [Tor's relay guidance](https://support.torproject.org/relays/legal-and-abuse/exit-relay-abuse/) distinguishes relay operation from user activity. Tor exit membership is context, not proof of compromise or a person's identity. Corroboration should outweigh raw database count.

## Next safe work

Publish the verified recovery milestone from committed source, then continue coordination with the active database/logging/timeline work. Preserve its uncommitted files. Test packaged Parental Controls and current dashboard routes through `--open-route`; record clean Release counts and package hashes. Keep installed elevation/signing, parental enforcement, clean-machine/reboot recovery and full v29 parity explicitly open.
