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

The diagram is the target design. Connected paths currently include read-only system/process, loaded-driver, and network inventory plus the advisory CISA KEV catalog. Detection, policy, action broker, durable evidence store, signed updates, and release signing are not implemented.

## Threat areas

| Area | Required safeguards | Current status |
|---|---|---|
| Local IPC | Named-pipe DACL, least privilege, versioning, bounded payloads, timeouts, replay-resistant action IDs if commands are later added | System, driver, and network snapshots use outbound-only servers with authenticated-local-user DACLs and bounded connection waits. UI clients now enforce a 1 MiB cap, JSON depth/duplicate checks, schema/list/text bounds; network inventory is limited to 32 interfaces and 256 TCP endpoints. Server identity verification and a narrower service-SID ACL remain open. |
| Service compromise | Narrow service identity, restricted handles, secure startup/recovery, signed binaries, service ACL review | Portable desktop starts only the fixed bundled service executable with no arguments, no shell, and no elevation; it owns and stops that child on graceful close. The service runs as the signed-in user for now. Installation identity, binary signature validation, crash recovery, and service ACL review remain open. |
| Malformed data | Strict JSON schemas, bounds, parser isolation, fuzzing, duplicate/unknown-field policy | Capability JSON and IPC payloads are size/depth bounded; duplicate JSON properties are rejected on bounded IPC and KEV parse paths. Broader fuzz coverage remains open. UI/Core JSON uses pinned Newtonsoft.Json 13.0.4 with type-name handling disabled. |
| Detection/content | TLS feeds, signature/integrity, provenance, expiration, rule validation, no executable feed content | One fixed-host HTTPS CISA KEV fetch has bounds, duplicate/CVE/date validation, and source/retrieval metadata. It has no persistent cache or detached signature validation; more feeds and rule engines remain unported. |
| Privileged response | allow-listed arguments, authorization, preview, audit, timeout, rollback, kill switch, opt-in defaults | No response action enabled or implemented |
| Local data | Minimize collection, DPAPI for secrets, restrictive ACLs, at-rest integrity, retention and deletion policy, verified backups | No persistent store implemented |
| Supply chain | Pinned NuGet/action versions, Dependabot, Windows CI, SBOM, reproducible signed release, provenance | SDK package versions and workflow action SHAs are pinned; Dependabot and Windows CI are configured. First remote CI run, SBOM, signing, and release provenance remain outstanding. |
| UI and availability | Dispatcher-only UI changes, bounded updates/queues, stale-data marker, reduced motion, input limits, graceful missing service | Dashboard renders live gauges and histories; dashboard, process, network, and driver routes distinguish an active desktop UI from unavailable local telemetry. The portable desktop starts its bundled service automatically and labels a connected read-only snapshot `ONLINE`; Settings provides a wired reduce-motion choice. Full accessibility and narrow/high-DPI review remain open. |

## Release blockers

1. Re-run and verify snapshot IPC ACL and service/client integration tests.
2. Define supported service identity and installer permission boundary.
3. Inspect first CI run and add SBOM/binary scanning before release.
4. Complete secure storage, feed/rule verification, and event-data retention design before collecting sensitive evidence.
5. Implement no system-changing response until policy and audit/rollback design passes review.
6. Add threat-model tests, fuzzing, dependency and binary scanning, SBOM, signing, and upgrade/recovery checks.
