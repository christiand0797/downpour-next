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

The diagram is the target design. At present, the only connected path is the service's read-only system snapshot. Detection, policy, action broker, durable evidence store, signed updates, and release signing are not implemented.

## Threat areas

| Area | Required safeguards | Current status |
|---|---|---|
| Local IPC | Named-pipe DACL, least privilege, versioning, bounded payloads, timeouts, replay-resistant action IDs if commands are later added | Snapshot-only; outbound-only server with an authenticated-local-user DACL, versioned payload, bounded client deadline, and passing integration test. Strict payload-size parsing, server identity verification, and narrower service-SID ACL remain open. |
| Service compromise | Narrow service identity, restricted handles, secure startup/recovery, signed binaries, service ACL review | Hosting scaffold only; installation identity not selected |
| Malformed data | Strict JSON schemas, bounds, parser isolation, fuzzing, duplicate/unknown-field policy | Capability JSON validates metadata; IPC snapshot needs size/schema bounds and fuzz coverage |
| Detection/content | TLS feeds, signature/integrity, provenance, expiration, rule validation, no executable feed content | Not ported |
| Privileged response | allow-listed arguments, authorization, preview, audit, timeout, rollback, kill switch, opt-in defaults | No response action enabled or implemented |
| Local data | Minimize collection, DPAPI for secrets, restrictive ACLs, at-rest integrity, retention and deletion policy, verified backups | No persistent store implemented |
| Supply chain | Pinned NuGet/action versions, Dependabot, Windows CI, SBOM, reproducible signed release, provenance | SDK package versions and workflow action SHAs are pinned; Dependabot and Windows CI are configured. First remote CI run, SBOM, signing, and release provenance remain outstanding. |
| UI and availability | Dispatcher-only UI changes, bounded updates/queues, stale-data marker, reduced motion, input limits, graceful missing service | UI prototype; visual validation pending |

## Release blockers

1. Re-run and verify snapshot IPC ACL and service/client integration tests.
2. Define supported service identity and installer permission boundary.
3. Inspect first CI run and add SBOM/binary scanning before release.
4. Complete secure storage, feed/rule verification, and event-data retention design before collecting sensitive evidence.
5. Implement no system-changing response until policy and audit/rollback design passes review.
6. Add threat-model tests, fuzzing, dependency and binary scanning, SBOM, signing, and upgrade/recovery checks.
