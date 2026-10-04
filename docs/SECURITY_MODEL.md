# Security model and hardening roadmap

## Boundaries

```text
Untrusted files / feeds / Windows events
                 │ bounded parsers + provenance + integrity checks
                 ▼
Sensors → normalized events → detections → evidence/alerts
                                      │
                                      ▼
                         recommendation and policy
                                      │ explicit authorization
                                      ▼
                        allow-listed action broker
                                      │ audited result + recovery
                                      ▼
                            Windows operating system

WinUI desktop ─── versioned local read-only IPC ─── Windows service
```

The diagram is the target design. Connected paths currently include read-only system/process, loaded-driver, network inventory, Windows event metadata, and the advisory CISA KEV catalog. A local operation journal is initialized, but detection, policy, action broker, durable evidence store, signed updates, and release signing are not implemented.

## Threat areas

| Area | Required safeguards | Current status |
|---|---|---|
| Local IPC | Named-pipe DACL, least privilege, versioning, bounded payloads, timeouts, replay-resistant action IDs if commands are later added | System, driver, network, event, Services, and alert snapshots use outbound-only servers. The DACL grants LocalSystem full control and the service's current user SID access; no Authenticated Users/Everyone ACE. Clients validate bounded schemas; network is limited to 32 interfaces/256 endpoints, Services to 512 rows, and alerts to 512 rows. The alert control pipe is a separate 1 KiB newline-framed channel with exact local triage, false-positive confirm, and re-arm intents, expected-state checks, and durable request IDs. FP rules use fixed channel/provider/event IDs only, require three user confirmations, and record rule-applied rows separately from individual suppression. No operating-system action is available. Server identity verification remains open. Portable UI/service run as the same signed-in identity, so this is not isolation from same-user malware. A future installed service must use a dedicated identity/SID. See `ALERTS.md`. |
| Service compromise | Narrow service identity, restricted handles, secure startup/recovery, signed binaries, service ACL review | Portable desktop starts only the fixed bundled service executable with no arguments, no shell, and no elevation; it owns and stops that child on graceful close. The service runs as the signed-in user for now. Installation identity, binary signature validation, crash recovery, and service ACL review remain open. |
| Malformed data | Strict JSON schemas, bounds, parser isolation, fuzzing, duplicate/unknown-field policy | Capability JSON and IPC payloads are size/depth bounded; duplicate JSON properties are rejected on bounded IPC and KEV parse paths. Broader fuzz coverage remains open. UI/Core JSON uses pinned Newtonsoft.Json 13.0.4 with type-name handling disabled. |
| Detection/content | TLS feeds, signature/integrity, provenance, expiration, rule validation, no executable feed content | One fixed-host HTTPS CISA KEV fetch has bounds, duplicate/CVE/date validation, source/retrieval metadata, and a versioned local cache with integrity-digest and age checks. It has no detached signature validation; more feeds and rule engines remain unported. |
| Windows events | Fixed local sources, query allowlist, low-privilege read, bounded cadence, minimize event data, explicit channel health | Samples 35 fixed event IDs across seven channels every 15 seconds while the service runs. Only bounded event metadata/stable summaries cross IPC; script/event bodies are not collected. Source permission/availability warnings are visible. Push subscriptions, Sigma/AMSI, Sysmon/ETW, cross-source correlation, investigation workflows, and broader alert lifecycle remain open. |
| Privileged response | allow-listed arguments, authorization, preview, audit, timeout, rollback, kill switch, opt-in defaults | No response action enabled or implemented |
| Local data | Minimize collection, DPAPI for secrets, restrictive ACLs, at-rest integrity, retention and deletion policy, verified backups | The service stores a schema-v2 operation journal and a separate schema-v1 event-alert database under a current-user/SYSTEM-only protected directory. The alert store has 30-day/10,000-row bounds and records triage transitions, but neither store is independently tamper-proof against the same-user identity. Alert data is metadata-only; no event content is persisted. See `ACTION_JOURNAL.md` and `ALERTS.md`. |
| Local review actions | Explicit target, valid transition, audit, bounded input, no arbitrary execution | Alert acknowledgment, suppression, and reopen operate on one stored alert ID with an expected-state check and idempotent request ID. These are local triage operations, not OS security actions; same-user malware can reach the pipe and modify this user's alert review state. |
| Supply chain | Pinned NuGet/action versions, Dependabot, Windows CI, SBOM, reproducible signed release, provenance | SDK package versions and workflow action SHAs are pinned; Dependabot and Windows CI are configured. First remote CI run, SBOM, signing, and release provenance remain outstanding. |
| UI and availability | Dispatcher-only UI changes, bounded updates/queues, stale-data marker, reduced motion, input limits, graceful missing service | Dashboard renders live gauges and histories; dashboard, process, network, and driver routes distinguish an active desktop UI from unavailable local telemetry. The portable desktop starts its bundled service automatically and labels a connected read-only snapshot `ONLINE`; Settings provides a wired reduce-motion choice. Full accessibility and narrow/high-DPI review remain open. |

## Release blockers

1. Re-run and verify snapshot IPC ACL and service/client integration tests.
2. Define supported service identity and installer permission boundary.
3. Inspect first CI run and add SBOM/binary scanning before release.
4. Complete bounded journal retention, secure storage, feed/rule verification, and event-data retention before collecting sensitive evidence.
5. Keep system-changing response disabled until the installed service identity, request authentication, verified consent, audit failure behavior, and rollback/recovery design pass review.
6. Add threat-model tests, fuzzing, dependency and binary scanning, SBOM, signing, and upgrade/recovery checks.
