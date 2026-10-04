# Security policy and development requirements

Downpour Next is security-sensitive software. Report vulnerabilities privately to the repository owner; do not publish exploit details before a fix is available. This repository is currently private and does not yet have a formal response SLA.

## Secure defaults

- Desktop runs as the signed-in user. The service uses the narrowest service identity and privileges required by each sensor.
- Observation, detection, recommendation, and response are separate stages. System-changing actions default off.
- IPC uses local named pipes, versioned bounded contracts, ACLs, and explicit timeouts. Never expose an unauthenticated network listener for local UI communication.
- No arbitrary shell, PowerShell, command-line, URL, path, or registry payload reaches the service. Use typed allow-listed operations only.
- Secrets use Windows-protected storage. Minimize or avoid personal data, command lines, clipboard content, file contents, browser data, and remote data transfer.
- Feed and rule inputs are untrusted. Require TLS, size/time limits, parser hardening, signature/integrity verification where available, and provenance metadata.
- Quarantine and evidence require integrity manifests, access control, bounded storage, collision handling, verified restore, and recovery procedures.
- Actions require policy authorization, operator preview where appropriate, audit records, bounded execution, a safe failure path, and tested rollback where possible.
- Dependencies and GitHub Actions are supply-chain inputs. Pin versions, review updates, keep secrets out of CI, and generate an SBOM before release.

## Current threat model

Assets include host telemetry, user settings, alert/evidence history, threat-feed state, rules/models, and any future quarantine contents. Threats include malicious local processes/users, malformed or spoofed IPC payloads, parser exploits, untrusted feeds/rules/files, dependency or update compromise, privilege escalation, denial of service, data disclosure, and unsafe automated remediation.

Currently implemented mitigations are limited: the named-pipe service sends small read-only snapshots; message contents contain process IDs/names and resource summaries; outbound-only pipe servers grant LocalSystem full control and the service's current user SID the access needed to open/read the endpoint; no Authenticated Users or Everyone ACE is present. Client connection and deserialization have a two-second deadline and a 1 MiB payload cap. No action broker or remote listener exists. Integration tests cover same-user local reads. Independent server identity verification remains open; a same-user malicious process can still spoof a local pipe, and the application is an early prototype, not an audited security product. If the service is later installed under a different account, define a dedicated service/client SID ACL instead of restoring Authenticated Users access.

## Before enabling a security feature

Record its data classification, trust boundary, least-privilege needs, privacy impact, failure behavior, test evidence, audit fields, and rollback plan in the feature documentation and queue. Run negative tests for access denial, malformed input, resource exhaustion, timeout, stale state, and recovery. Do not mark it implemented until the evidence is recorded.
