# v2 continuation audit — 2026-10-07

The owner requested full functional v29 parity, no placeholder or simulated protection, explicit elevation for admin operations, a new GitHub release, and durable progress records. v29 remains read-only. This document records the repository-wide inventory and targeted source review; it is not a claim that every line received a complete security audit.

## Current inventory and evidence

The initial checkout had 472 tracked files, including 308 C# files, 40 XAML files, 33 YARA files, seven projects, 129 source-module entries, and 38 committed routes. The working tree adds an AntiStalker route and host-isolation draft. The parity checklist names 215 route workflows plus non-route work; route existence is not acceptance evidence. Historical context and feature docs describe older milestones and must be read with the newest checkpoint.

Baseline restore and Debug build passed with zero warnings/errors. Baseline tests: 840 passed, one failed due to the additional draft route. The route test now verifies all 38 existing route IDs and unique titles/IDs while allowing additional routes. The first full run after detection fixes passed 879 tests, including the preserved draft tests; clean committed release verification is recorded separately.

## Detection fixes implemented in this continuation (DN-005)

- Sysmon live observations previously became a SecurityEventSnapshot that the repository validator rejected: no Sysmon IDs existed in the shared alert catalog. Corrected catalog validation and a bounded projection now persist review events 8, 9, and 25; replay preserves suppression. Other Sysmon metadata remains telemetry, rather than declaring ordinary process/network/file activity malicious. Event labels were corrected against [Microsoft's Sysmon reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Internal error 255 becomes a health warning, undocumented 256–258 are removed, and clipboard activity 24 is excluded by privacy policy.
- Sysmon now actually polls every 15 seconds, with a one-second per-source read budget, as the earlier push warnings claimed. The latest bounded metadata snapshot is published, and missing channels, read failures, internal errors, queue loss, and persistence failures are visible in alert health. Sysmon installation/configuration is never changed automatically.
- AMSI initialization/scan errors previously returned NOT_DETECTED; higher valid malware results were not recognized. Scan results now include HRESULT and an optional provider verdict. Failed scans are Unknown. The native uninitialize signature is void, library loading is System32-only, context lifetime is serialized with scans, and missing-provider retries are bounded to 30 seconds. Result >=32768 is detected, following [Microsoft's AMSI result contract](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result).
- Sigma remains available during AMSI failure. Health warnings survive publications from other workers. Dedup has a five-minute TTL and a 4096-entry hard cap; event time distinguishes reused record IDs. Script text remains bounded and in-memory; no snippets enter alerts. Script subscriptions own and dispose their watcher/property selector.
- Version metadata is centralized in Directory.Build.props at 0.1.16; forensic collector metadata uses the compiled assembly version.

## Open implementation gaps and next safe work

| Queue | Actual remaining work |
|---|---|
| DN-005 | ETW adapters, stronger cross-source correlation, complete investigation lifecycle, sensor retry/health and loss acceptance, live channel-by-channel event verification. |
| DN-006 | Full affected-version/range/CPE analysis, feed and rule lifecycle/integrity, scan coverage and v29 acceptance fixtures. |
| DN-008 | Admin elevation through a narrow action helper, timeout/rollback/audit gates for each privileged operation, recovery independent of portable service lifetime, action history/retention. Do not enable the isolation draft until the four blockers in AGENT_COORDINATION.md are fixed. |
| DN-009 | Finish operational adaptive/deception CIS beyond the new measured review/integrity slice; all five AEGIS layers, continuous ransomware monitoring/recovery, isolated detonation, memory analysis, hunting, actual parental enforcement, cleanup deletion, VPN kill-switch, IoT controls and emergency workflows through validated brokers. Existing read-only inspections are useful slices, not complete protection. |
| DN-010 | Clean release packaging, publish/verify v0.1.16, signing, installed restricted service, installer/upgrade/uninstall and recovery, real Windows Runtime deployment validation. |
| DN-012 | Driver lifecycle execution with verified packages, export/rollback, authorization, UAC and denial/recovery tests. Current prepare-only broker is not installation capability. |
| DN-002 | Native route/picker click-through, keyboard/high contrast/reduced motion, narrow/high-DPI layout and clean-machine deployment. |

Windows adapters still appear in some Core inspectors and need migration into Service where appropriate. Build/test coverage is not native UI or privileged-action acceptance. v0.1.16 retained a labeled CIS concept demo; the subsequent DN-009 slice removes scripted protection and connects measured review plus explicit package-file consistency checks (docs/CIS.md). This remains incomplete CIS parity. Neither slice adds host isolation or administrator escalation.

## Release source boundary

Preserve all pre-existing uncommitted files. Commit only owned detection/version/docs/test changes on main. Build the release from a new clean detached checkout under artifacts inside v2; exclude active DN-008/AntiStalker drafts. The latest remote release at audit time was v0.1.14; v0.1.15 archives were local. GitHub CLI authentication is available. Release validation, source commit, archive hash, exact commands, known failures, and next tasks belong in the newest SHARED_CONTEXT checkpoint and WORK_QUEUE notes.
