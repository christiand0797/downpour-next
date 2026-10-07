# Action broker: threat model and quarantine design (DN-008, for owner review)

**Status (2026-10-07):** the owner approved building and enabling actions phase by phase. Phase 1 (quarantine and restore) is implemented and on: see `QuarantineExecutor`, `QuarantineVault`, `QuarantineActionPipeWorker`. Deviations from the original text: caller verification uses parent-process identity and install path until signing exists (D2); the restore copy is kept until the user deletes it (no 7-day purge yet); a quarantine-actions switch in Settings defaults on per the owner's decision. Phases 2–5 are not built.

**Original status:** design for review. The owner decided "design first" (SECURITY.md, 2026-10-07). This builds on `ACTION_BROKER.md` (contracts, catalog, feature switches, validator) and `ACTION_JOURNAL.md` (journal). It covers what those leave open: the threats, the caller authentication, the crash-safe quarantine and restore protocol, the order in which actions get enabled, and the tests that must pass before each one.

## 1. What we are protecting and from whom

**Assets:** user files (a wrong quarantine destroys data); system integrity (a wrong kill or block breaks Windows or the network); quarantined malware (must not escape or be restored silently); the audit trail; Downpour itself.

**Adversaries:**
1. **Malware running as the signed-in user.** This is the main one. In portable mode the sensor service runs as that same user.
2. A malicious local process that talks to the named pipes directly.
3. Malware that wants a *false positive acted on*: getting Downpour to quarantine a security tool or a system file, or to block a legitimate IP.
4. Malware that wants a *quarantined file restored*.
5. Crashes, power loss, and full disks in the middle of an action.

**Accepted limit, stated plainly:** malware running as the same user can drive the desktop UI and can tamper with same-user files, including the quarantine store and journal. Full protection against that needs the service to run under a different identity (decision D1 below). The design keeps that upgrade path open and does not pretend to protect against it in portable mode.

## 2. Abuse cases and controls

| Abuse case | Control |
|---|---|
| A process other than the Downpour desktop sends action requests | A separate action pipe (never the read-only snapshot pipes). The server gets the client PID (`GetNamedPipeClientProcessId`), resolves its image (`QueryFullProcessImageName`), and requires the Downpour desktop executable from the install directory with a valid Authenticode signature from the Downpour publisher once releases are signed (DN-010). Until signing exists, actions stay disabled in release builds. |
| A request without real user intent | Every non-dry-run request needs a per-request consent token. The service mints a one-time nonce bound to (action, object, hash) after the desktop shows the preview dialog, and the request must echo it within 60 s. No batch "remediate all" without an itemized preview. v29's AUTO remediation stays off (decision D3). |
| Quarantining a system file or security tool | A deny-list checked on the *final* path (after `GetFinalPathNameByHandle`): `%SystemRoot%`, `Program Files\Windows Defender`, other installed AV products, the Downpour install and state folders, files with a valid Microsoft signature, and boot or driver files. Denials are audited. |
| Path tricks: junctions, symlinks, hard links, 8.3 short names, alternate data streams, TOCTOU | Open the file once with `FILE_FLAG_OPEN_REPARSE_POINT` and deny-write sharing, reject reparse points and files with more than one hard link, resolve and re-check the final path from the handle, hash from the same handle, and delete through the same handle (`FileDispositionInfoEx`, POSIX semantics). The path is never reopened by name after validation. |
| Restoring malware silently | Restore needs its own consent, verifies the decrypted hash matches the manifest, never overwrites an existing file, and records the result in the audit trail. Restoring a file flagged CRITICAL needs a second confirmation. |
| Filling the disk with quarantine or audit data | A quarantine quota (default 2 GiB, oldest-first expiry only after user confirmation), a 256 MiB per-file cap (as in the inspector), and journal retention. If storage fails, the action is not performed (fail closed). |
| Killing critical processes | (Later phase.) Deny PID 0/4, csrss, wininit, services, lsass, smss, winlogon, protected or PPL processes, and Downpour. Only processes named in an open alert can be killed, with the PID plus the process creation time bound in the request to avoid PID reuse. |
| Firewall changes that lock the user out | (Later phase.) Rules use the `DownpourNext_` prefix, block specific remote IPs only, never "block all", have an expiry, and are listed and removable from the Firewall page. |
| Replay of an old request | The request ID is unique in the journal (already implemented), plus the consent nonce. |

## 3. Quarantine protocol (write-ahead, crash-safe)

This follows v29 `quarantine_core.py`: AES-GCM, a DPAPI-protected key, a manifest written before the original is deleted, and hash-verified restore.

1. **Prepared** (journal). Validate the request, consent nonce, caller, and deny-list. This step already exists, up to the hash.
2. Open the source by handle (rules in section 2) and confirm its SHA-256 matches the request.
3. **Stage.** Stream-encrypt into `state\quarantine\<objectId>.dqf` with AES-256-GCM in 64 KiB chunks, with a per-file nonce prefix and chunk counter (as in v29 format v2). The key is random, stored DPAPI-protected, and never leaves the service. Write a manifest containing:
   - original path, size, and SHA-256;
   - attributes and timestamps;
   - the owner and DACL as SDDL;
   - the Mark-of-the-Web zone identifier;
   - the alert ID.

   Flush both files (`FlushFileBuffers`). Journal: **ContentStaged**.
4. **Verify.** Decrypt the staged file in streaming mode and compare its hash with the manifest. On a mismatch, delete the staged copy: Failed, original untouched.
5. **Remove the original** through the open handle with POSIX delete. Journal: **Quarantined**. Raise an audit event and update the alert.
6. **Crash recovery** (the typed verifier the journal is missing) at service start, for each operation that isn't finished:
   - Staged copy verifies and the original still exists with the same hash: delete the staged copy and mark it **RolledBack**.
   - Staged copy verifies and the original is gone: mark **Quarantined**.
   - Staged copy missing or corrupt and the original present: mark **Failed** (nothing changed).
   - Both missing: **RecoveryRequired**. Show this in the UI. It is never resolved silently.

**Restore:**
1. Requires consent.
2. Decrypt to a temporary file in the target folder, then verify the hash.
3. Move into place only if the target name does not exist; otherwise restore under a user-chosen name.
4. Re-apply the timestamps and the DACL if the user owns the target, plus the Mark-of-the-Web.
5. Journal: **Restored**.
6. Keep the encrypted copy for 7 days unless the user deletes it.

## 4. Enablement order and gates

Each phase stays behind its own feature switch, default off, and is enabled only after its tests pass and you approve the phase.

1. **Quarantine and restore** of user-selected or alerted files, using the protocol above.
2. **Process termination** for processes named in alerts (PID plus creation time, with the deny-list).
3. **Firewall block of a remote IP** (expiring `DownpourNext_` rules) and **removal of v29's leftover `DOWNPOUR_*` rules**, which needs only the firewall page's existing detection.
4. **USB device block** for a specific device instance, reversible.
5. **Host isolation / emergency lockdown** last, because it can cut off remote recovery. It needs a built-in automatic expiry.

**Tests required before any phase is enabled:**
- Denial: switch off; no or expired consent; caller not the Downpour desktop; deny-listed path; reparse point; hard link.
- Crash injection after each journal state, confirming the recovery outcome above.
- Disk-full and timeout behavior.
- Hash mismatch.
- Restore never overwrites.
- Audit records exist even for denials.
- Performance with a 256 MiB file.

## 5. Decisions needed from the owner

- **D1, service identity.** Keep portable same-user mode, where quarantine is only as safe as the user account, or ship an installed Windows service under a dedicated account so same-user malware cannot tamper with the quarantine store or journal. Recommended: keep portable for phase 1 and plan an installed service before phases 2–5.
- **D2, signing.** Caller authentication relies on Authenticode, so release signing (DN-010) must come before any action ships in a release build. Approve that ordering.
- **D3, auto-remediation.** v29 had an AUTO switch that remediated without asking. Recommended: off for all phases. Every action is individually confirmed.
- **D4, quarantine quota.** Default 2 GiB with confirmed expiry. Adjust if you want.
