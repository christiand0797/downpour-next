# Building a Feature-Preserving Downpour Successor

This guide describes how to replace Downpour's Python/Tkinter implementation with a native Windows application that can support a richer interface and clearer subsystem boundaries without dropping its security, monitoring, response, or operational features. It is an architecture and migration plan; it does not claim the successor has been implemented.

## Recommendation

Use **C# on .NET 10 LTS with WinUI 3 and the Windows App SDK** for the Windows desktop application. Put long-running monitoring and privileged operations in a separately installed .NET Windows Service. Keep detection engines and security actions behind interfaces so the user interface never owns security policy or privileged system handles. Consider Rust libraries only for measured CPU-bound components after profiling; do not split the first release across several languages.

Microsoft currently recommends WinUI 3 and the Windows App SDK for new native Windows desktop applications. WinUI 3 uses XAML with C# or C++, and supports adaptive, high-DPI Windows UI. .NET 10 is listed as an active LTS release through November 14, 2028. These are the current recommendations as of October 3, 2026; recheck support dates and stable Windows App SDK releases when implementation begins. See [WinUI 3](https://learn.microsoft.com/en-us/windows/apps/winui), [Windows App SDK](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/), and the [.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy).

This stack is a better fit for a Windows-first product because it gives the team a native XAML UI, first-party Windows app APIs, static types, and a supported Windows-service hosting model. A language switch alone does not guarantee faster scanning or lower memory use; benchmark the actual workload and preserve the current detections as behavior fixtures. If cross-platform support becomes a product requirement, compare that requirement separately before locking the UI framework.

## What must remain equivalent

Downpour's main window is a roughly 58,000-line application file with 33 registered UI destinations and 28 performance gauges. It also has more than 40 supporting security modules and a broad set of monitors, analyzers, threat feeds, remediation actions, reports, and hardening features. Use the repository's current source and [module map](MODULE_MAP.md) as the authoritative inventory; older readmes and status files contain historical counts.

Create a checked-in `capabilities.yml` or equivalent registry before porting. Give every current capability a stable ID and record its source module, data sources, permissions, outputs, UI destination, persistence needs, tests, target owner, and parity status. Keep these records until the Python implementation is retired. Do not use the number of screens or classes as the definition of parity.

| Capability family | Current behavior to inventory | Successor boundary |
|---|---|---|
| Dashboard and operations | Security status, health, performance gauges, CPU/RAM/GPU/disk/network metrics, process tables, history charts, status messages, export | WinUI shell, dashboard view models, metrics read model |
| Process and behavior monitoring | Process inventory, command-line and parent/child behavior, injection indicators, persistence, privilege escalation, LOLBins, DGA, beaconing, IOC matches | Process sensor, normalized event pipeline, detection services |
| Network and device monitoring | Connections, DNS, firewall rules, Wi-Fi, Bluetooth, USB, IoT fingerprinting and botnet indicators | Network/device sensor adapters, network analysis services |
| File and ransomware protection | File integrity, canaries, entropy and rename behavior, YARA/YARA-X rules, hash checks, static PE and EMBER analysis, quarantine and rollback | File event adapter, analysis workers, versioned quarantine service |
| Windows telemetry | Windows Event Log push/polling, Sysmon, ETW, registry, services, drivers, named pipes, COM, boot integrity, TLS, clipboard, DPAPI, print spooler, AD/Kerberos | Windows sensor adapters emitting versioned events |
| Threat intelligence and vulnerability data | Threat feeds, feed integrity, indicators, actors, Sigma/YARA rules, CVE/KEV/EPSS/CEV, MISP/STIX/TAXII, cache and update state | Feed connectors, normalized intelligence store, rule catalog |
| Response and hardening | Alert triage, process termination, IP/firewall blocks, host isolation, remediation, Defender compatibility, system hardening, parental controls, cleanup | Policy engine plus narrow privileged-action broker with audit and rollback |
| Forensics and reporting | Memory analysis, scan findings, evidence collection, timelines, history, CSV/JSON/HTML/Markdown export | Evidence store, report services, export adapters |
| AEGIS and resilience | Five AEGIS layers, self-checks, sensors, sharded context, logging, configuration, shutdown and recovery | Explicit domain services, durable state, health and diagnostics |

For each row, enumerate individual features and edge cases in the capability registry. For example, “quarantine” includes encryption, manifest integrity, restore verification, legacy migration, collision handling, and recovery behavior; counting one screen as one feature would miss those requirements.

## Target architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ Downpour.Desktop — WinUI 3, XAML, MVVM                      │
│ Navigation · dashboards · virtualized tables · reports      │
└────────────────────────────┬────────────────────────────────┘
                             │ versioned local IPC
┌────────────────────────────▼────────────────────────────────┐
│ Downpour.Service — Windows Service, least privilege needed   │
│ Policy/action broker · lifecycle · health · audit            │
├─────────────────────────────────────────────────────────────┤
│ Application services: alerts · cases · scans · remediation   │
├─────────────────────────────────────────────────────────────┤
│ Detection: Sigma · YARA · PE/EMBER · behavior · ML · rules   │
├─────────────────────────────────────────────────────────────┤
│ Event bus: bounded channels · correlation · backpressure     │
├─────────────────────────────────────────────────────────────┤
│ Sensors: ETW · Event Log · process · network · file · device │
├─────────────────────────────────────────────────────────────┤
│ Storage: SQLite · encrypted quarantine · evidence · settings │
└─────────────────────────────────────────────────────────────┘
```

### Desktop application

- Use MVVM: XAML views render state; view models expose observable data and commands; domain services make decisions. Do not put detection rules, database access, or administrative operations in code-behind.
- Use a stable `NavigationView` for the module catalog. Group the 33 current destinations by workflow, preserve a searchable command palette and favorites, and keep one route definition per stable ID. Cache a page by route ID where its state should persist. Use closable tabs only for user-opened cases or investigation records, not as a second copy of the module navigation.
- Implement the performance dashboard as an adaptive card grid. At wide widths show more gauges per row; at narrow widths move secondary details below the primary metrics. Use vector or composition charts and virtualized `ItemsRepeater`/table controls for growing result sets. Keep all key values available as text and in screen-reader names; color and animation are supplementary.
- Support keyboard navigation, focus visibility, text scaling, high-contrast themes, DPI changes, reduced motion, and resizable windows from the first shell. Microsoft guidance recommends adapting layout at narrow widths rather than shrinking every control; see [Windows app accessibility](https://learn.microsoft.com/en-us/windows/apps/design/accessibility/accessibility) and [design for productivity in WinUI apps](https://learn.microsoft.com/en-us/windows/apps/get-started/line-of-business/design-for-lob).

### Service and privilege boundary

- Run the desktop application as the signed-in user. Run only the sensors that need persistent access and narrowly privileged actions in a Windows Service. Microsoft documents hosting a .NET `BackgroundService` as a Windows Service in its [Windows Service guide](https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service).
- Protect local IPC with an ACL limited to the service identity and approved interactive users. Version every request and response. Validate size, enums, paths, process IDs, and action parameters at the service boundary. A client must not be able to submit arbitrary command lines or registry scripts.
- Separate observation from action. Detection services produce evidence and recommended actions; a policy service checks user policy and authorization; a broker executes a narrow allow-listed operation and records its result. Keep destructive actions configurable, attributable, and reversible where the operating system permits it.
- Do not add a kernel driver merely to match a “low-level” label. Start with documented Windows APIs and existing telemetry providers. ETW has explicit controller, provider, and consumer roles, supports real-time event delivery, and reports lost-event statistics; design session ownership and loss monitoring into the sensor service. See Microsoft's [ETW overview](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing).

### Event and data contracts

Define versioned contracts before moving individual modules. A normalized event should include at least: schema version, event ID, UTC timestamp, provider, host, process and parent identifiers when available, category, severity, correlation/case ID, evidence fields, and a source-health marker. Preserve the original source payload where policy permits so future parsers can improve without losing evidence.

Use bounded `Channel<T>` pipelines with explicit per-event backpressure. Never silently drop critical security events; expose queue depth, oldest-item age, producer health, and drop counts. Coalesce high-frequency gauge updates separately from forensic event delivery. Keep slow disk, network, model, and feed work away from the UI dispatcher.

Use SQLite for configuration, alert metadata, intel cache, history, and migration state. Keep large evidence blobs and quarantined content in a separately managed store with integrity manifests. Use versioned, transactional migrations and preserve old data until a restore check succeeds. Protect secrets with Windows identity-bound storage such as DPAPI; never serialize credentials into ordinary settings.

## Migration plan

### Phase 0 — Establish a parity baseline

1. Freeze a source revision and build the capability registry from `downpour_v29_titanium.py`, `docs/MODULE_MAP.md`, `SHARED_CONTEXT.md`, active modules, configuration, rules, models, and tests.
2. For every capability, capture representative benign, suspicious, unavailable-data, permission-denied, timeout, malformed-input, and recovery cases. Save normalized expected evidence and action decisions as fixtures.
3. Mark each feature `implemented`, `partial`, `optional`, `legacy`, `declined`, or `unknown`; verify whether each “active” module is actually wired into a live path.
4. Record current startup time, idle memory, event throughput, queue loss, scan latency, UI refresh rate, and response latency on a named reference machine.

### Phase 1 — Build the native foundation

Create a solution with separate `Desktop`, `Service`, `Contracts`, `Core`, `Infrastructure`, `Detection`, and `Tests` projects. Establish dependency injection, structured logging, configuration, SQLite migrations, local IPC, health endpoints, versioned event contracts, and install/uninstall/upgrade flows. Build the shell and an empty dashboard first. Verify service recovery, app shutdown, upgrade rollback, and privilege boundaries before enabling system actions.

### Phase 2 — Replace the interface while preserving behavior

Port navigation, status, health, performance metrics, scan history, and report viewing to WinUI. During development only, the new desktop may call a tightly scoped local compatibility process that wraps Python modules behind versioned contracts. Keep that bridge off by default in packaged releases; do not let it become an unreviewed permanent privilege path. This stage makes GUI feedback possible without claiming the detection engines have already been migrated.

### Phase 3 — Move read-only sensors and detections

Port sensors in small vertical slices: process and event-log events, ETW/Sysmon, file and registry monitoring, network/DNS, then devices and hardware. For every slice, compare event counts and normalized outputs against the frozen fixture corpus. Port deterministic rules before learned behavior. Preserve Sigma and YARA rule compatibility or document and test a deliberate format migration.

Move ML models with explicit validation. Do not load Python pickle files from the new application. Export supported models to a safer interchange format such as ONNX or reimplement the scorer from documented inputs, then compare score distributions, calibration, missing-feature behavior, and false-positive fixtures against the Python baseline. Keep model files versioned with feature-schema IDs.

### Phase 4 — Move stateful response safely

Port quarantine, restore, firewall actions, host isolation, process actions, remediation history, hardening, and parental-control enforcement only after sensor and detection parity is demonstrated. Use dry-run mode, audit records, backups, rollback, and a per-action policy switch. Run the service in observe-only mode first; require an operator to compare old and new recommendations before enabling automatic actions.

### Phase 5 — Cut over and retire the bridge

Run both implementations in shadow mode on the same event fixtures and, where appropriate, on a consenting test machine. Compare alert decisions, evidence, performance, and storage recovery. Switch one capability family at a time. Keep a documented rollback path to the last signed release. Remove the Python runtime bridge only when every required capability has an owner, a passing acceptance suite, a migration path, and an operational replacement.

## Parity and release gates

Do not call the successor feature-complete until all of these gates pass:

1. **Inventory:** Every current capability has a stable registry ID, an explicit target owner, and a disposition; there are no unexplained “unknown” or orphaned features.
2. **Detection parity:** Frozen fixtures produce equivalent or intentionally reviewed decisions and evidence. Include false-positive fixtures and malformed/partial data, not only malware examples.
3. **Sensor health:** ETW/Event Log providers, polling fallback, permission failures, service restart, buffer loss, event deduplication, and shutdown have tested outcomes.
4. **Action safety:** Every response command is allow-listed, authorized, audited, bounded by timeout, and covered by rollback or an explicit irreversible-action test.
5. **Data continuity:** Settings, baselines, cases, rule configuration, model versions, and quarantine manifests migrate and restore from a backup without data loss.
6. **UI behavior:** No duplicated navigation destinations; dashboards and tables resize at narrow, standard, high-DPI, and ultrawide sizes; live updates remain responsive under event load; keyboard and screen-reader workflows work.
7. **Performance:** Compare against the Phase 0 machine and workloads. Set measurable budgets for idle CPU/memory, ingestion throughput, queue age, scan latency, and UI input latency before tuning.
8. **Operations:** Signed installer and service, least-privilege defaults, upgrade/recovery/uninstall checks, support logs, and a tested release rollback exist.

## First implementation backlog

1. Add the capability registry and source-to-feature audit script.
2. Define the event, alert, case, scan, action, and health contracts with schema versioning.
3. Prototype the WinUI shell with `NavigationView`, route de-duplication, responsive gauge cards, and a virtualized findings table.
4. Prototype the .NET service, ACL-protected IPC, structured logs, and observe-only event pipeline.
5. Port one narrow vertical slice—performance telemetry or read-only process inventory—and compare it with Downpour fixtures.
6. Review privilege boundaries, installer lifecycle, and data migration before moving remediation features.

## Official references

- [WinUI 3 overview](https://learn.microsoft.com/en-us/windows/apps/winui)
- [Windows App SDK overview](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/)
- [.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy)
- [.NET Windows Service hosting](https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service)
- [ETW overview](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [WinUI accessibility](https://learn.microsoft.com/en-us/windows/apps/design/accessibility/accessibility)
- [Responsive layout and navigation guidance](https://learn.microsoft.com/en-us/windows/apps/get-started/line-of-business/design-for-lob)
