# Windows Event Monitor

## Working behavior

While `Downpour.Service` is running, the service samples seven fixed local Windows Event Log channels every 15 seconds and keeps the latest bounded snapshot in memory. The Event Monitor page refreshes from the service snapshot, with search and severity filters. It does not need to remain open for collection to continue.

The current allowlist follows v29's 35 event/channel pairs:

- **System:** 104 (log cleared), 7045 (service installed)
- **Security:** 4698, 4699, 4720, 4726, 4728, 4732, 4738, 4740, 4776, 1102, 4625, 4663, 4672, 4673, 4688, 4697
- **PowerShell/Operational:** 4104
- **Windows Defender/Operational:** 5001, 5003, 5004, 5007, 5010, 5012, 1116, 1117
- **TerminalServices LocalSessionManager/Operational:** 21, 22, 24, 25
- **TerminalServices RemoteConnectionManager/Operational:** 1149
- **Windows Firewall With Advanced Security/Firewall:** 5152, 5156, 5157

Event message bodies, script text, usernames, process command lines, and event XML are not sent to the desktop or persisted. The service sends the channel, provider name, event ID, record ID, UTC timestamp, fixed severity/technique label, and a stable summary. Windows/Defender/firewall/RDP channels may be disabled or permission-restricted; each unavailable source is shown as a warning, not an empty healthy sensor.

Windows Security Event 4625 is not shown individually. The service runs a bounded five-minute query and emits one high-severity brute-force observation at ten or more failures. The count is capped at 100 per sample and is only a threshold signal; it does not identify the account or source address.

## Limits and parity work

This is an event observation slice, not the finished detection or response system. The service polls every 15 seconds; v29's push subscription, alert queue/lifecycle, investigation evidence, and suppressions are not yet ported. PowerShell 4104 script contents are intentionally not collected, so the original heuristic/Sigma/AMSI script analysis is not implemented here. Sysmon, ETW, registry/file/device watchers, cross-source correlation, durable alert history, notification delivery, and response actions remain outstanding. See `WORK_QUEUE.json` DN-004, DN-005, DN-007, and DN-008.

No event automatically changes system state. All data remains in memory and is cleared when the sensor service exits.
