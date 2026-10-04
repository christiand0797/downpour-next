# Local security alerts

Downpour Next currently projects its fixed Windows Event Log observations into a persistent alert list. It is a local rule-based feed, not a general detection engine and not full Downpour v29 alert parity.

## Data flow

```text
Fixed event/channel allow-list
    → bounded 15-second SecurityEventSnapshot
    → validated SQLite upsert
    → bounded output-only Downpour.SecurityAlerts.v1 snapshot pipe
    → Alerts page
```

The alert monitor ingests only `SecurityEventClient`-validated records. Each finding inherits title, severity, and ATT&CK technique from `SecurityEventCatalog`; the app displays no confidence score because no statistical or content-based confidence model exists. It does not collect event XML, message bodies, usernames, script text, command lines, or file contents.

## Stable identity and deduplication

- Ordinary events are keyed by event log plus EventRecordID and event ID. Their lowercase 64-character alert ID is a SHA-256 identifier derived from that key and the `downpour-alert-v1` namespace.
- Missing-record-ID rows use a clearly weaker fallback key containing channel, provider, event ID, and minute. Such records can be coalesced and are not as unique as EventRecordID-backed rows.
- Failed-logon burst observations use a five-minute time bucket, so polling updates the same finding rather than creating a new row every 15 seconds. Reported occurrence count is the maximum observed for that bucket, not a sum of repeated polls.
- Repeated ingestion updates last-seen time and occurrences while preserving state. Acknowledged/suppressed findings do not reopen just because the event remains in the source lookback.

## Persistence and limits

The service stores `alerts.v1.db` under `%LOCALAPPDATA%\DownpourNext\state`, in the same current-user/SYSTEM ACL directory as the operation journal. Schema v2 migrates existing v1 alert stores in place. SQLite WAL and FULL synchronous mode are enabled. The store retains at most 10,000 alerts and 30 days by last observation, returns the latest 512 entries over the UI pipe, and records local state transitions with request IDs for retry safety. Acknowledgment and suppression history is local, not independently tamper-proof; same-user malware can modify the database.

## Local triage channel

`Downpour.SecurityAlerts.v1` is output-only. `Downpour.SecurityAlerts.v1.Control` accepts a newline-framed JSON message capped at 1 KiB and a strict five-field schema. It accepts local triage state transitions among `Open`, `Acknowledged`, and `Suppressed`, plus explicit `FalsePositive` and `RearmFalsePositive` review intents, all with expected-state checks, fixed request IDs, strict alert-ID grammar, and a local-user/SYSTEM pipe ACL. A false-positive fingerprint is SHA-256 over the fixed channel, provider, and event ID tuple; event message text is not collected, normalized, or used for matching. Three separately confirmed user actions create a persistent rule. Matching alerts are suppressed, with an explicit list of only automatically suppressed row IDs so re-arming does not reopen alerts the user had individually suppressed. Re-arm clears the fingerprint rule and reopens only rows the rule itself suppressed. Request outcomes persist for retry safety and are capped at 10,000 rows / 30 days. These local review rules cannot start processes, control services/drivers, alter files, change firewall/security settings, or execute commands.

The control pipe runs under the same signed-in account as the portable UI. Its ACL is a local boundary against other unprivileged accounts, not protection from malware already running as the same user. System-changing action authorization still requires an installed restricted service identity, authenticated client identity, explicit consent, durable action audit, and recovery design.

## Investigation export

The Alerts page offers a user-initiated JSON investigation export through the Windows save picker. Schema version 2 exports one validated point-in-time snapshot of up to the latest 512 retained alerts, including fixed titles/rules, alert IDs, severity, technique, event source IDs, timestamps, occurrence count, triage state, source-health warnings, and supported cross-channel patterns. It does not include raw Windows event XML/messages, usernames, command lines, or file contents. The export builder rejects snapshots outside the existing alert contract and caps serialized output at 1 MiB. The user chooses the destination; Downpour does not upload or automatically share the report. The resulting file becomes user-controlled data at that destination.

## Cross-channel patterns

The Core correlation engine evaluates only a validated snapshot of at most 512 alerts. It currently reports two fixed patterns: System 7045 with Security 4697 within two minutes, and Security 1102 with System 104 within ten minutes. Pairs are selected by nearest timestamp, each source alert is used at most once per rule, and individually suppressed alerts are excluded. Correlation identifiers are deterministic hashes of the rule ID and the two evidence alert IDs. The engine does not persist or change source alerts.

The UI labels these patterns as time-proximity evidence. The export includes each pair's alert IDs and event IDs/record IDs plus a plain limitation statement. Since the event collector does not retain the service name, target log, principal, process, or a shared operation identifier, temporal proximity cannot establish a common actor or prove that two records describe the same action. These patterns are not a confidence score or standalone proof of compromise. Missing events, disabled audit policy, permissions, retention, and the 512-alert window can prevent detection. No response action is triggered.

## Remaining alert parity

The first cross-channel correlation slice is now connected to the UI and export, but does not yet include Sigma/AMSI script analysis, Sysmon/ETW, alert grouping by campaign or process, rich investigation timelines, notification routing, richer user-defined suppression criteria, or the full v29 alert lifecycle. Keep the existing Events route as the raw bounded observation view and use Alerts for retained unique event findings.
