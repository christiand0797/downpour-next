# Feature parity and migration plan

This project aims to preserve every Downpour v29 capability and improve its usability, performance, and maintainability. [`../capabilities.json`](../capabilities.json) preserves the 33 original UI destinations and adds one new Drivers destination. [`../source-modules.json`](../source-modules.json) tracks all 71 entries in the source module map and retains their original active, legacy, reference, orphaned, or declined status. These lists are starting inventories; reconcile them against the source's wired features, settings, scheduled jobs, rules, data stores, and workflows before claiming parity.

## Principles

1. **Parity before expansion.** New features do not replace existing security behavior.
2. **No decorative completion.** UI-only routes remain `planned` or `prototype` until their engine and data paths work.
3. **Service isolation.** Continuous collection and privileged operations belong in the Windows service, with narrow contracts to the desktop process.
4. **Visible trust boundaries.** Show sensor health, data age, permission state, and action outcomes. Avoid fabricated zeroes or silent failures.
5. **Safe response.** Destructive or disruptive responses require explicit policy, confirmation where appropriate, reversible steps when possible, and an audit record.

## Stages

### 0. Foundation (underway)

- Native desktop shell, route registry, dark visual system, rain and crescent motif.
- Service host runs in observe-only mode.
- Define versioned contracts and a supported Windows / .NET release baseline.

### 1. Observe and inventory

- Port process, network, system resource, and Windows service snapshots.
- Add health and freshness states to the dashboard.
- Use a single sensor snapshot per interval, then fan it out to consumers.
- Reconcile the registry against every feature, watcher, setting, and background task in the Python source.

### 2. Detection and triage

- Port threat ingestion, suspicious process/network analysis, ransomware behavior, vulnerability checks, and intelligence feeds.
- Build alert lifecycle, evidence, timeline, search, and export flows.
- Preserve offline behavior and validate feed integrity / cache expiration.

### 3. Protection controls

- Port firewall, DNS, Wi-Fi, USB, hardening, Defender compatibility, and AEGIS controls.
- Establish authorization, preview/dry-run, rollback, and audit behavior before enabling system-changing operations.

### 4. Advanced workflows

- Port memory forensics, sandbox, threat hunting, cleanup, remote access, parental controls, and emergency response.
- Document platform limitations and require explicit consent for sensitive collection.

### 5. Feature parity gate

- Compare each original screen and callable workflow with the new application.
- Confirm all scheduled jobs and response paths have a clear owner and error state.
- Verify upgrade, uninstall, recovery, logging, and performance behavior on supported Windows versions.
- Only then mark all equivalent routes `implemented` and plan enhancements.

## Future improvements after parity

Potential improvements include customizable workspaces, richer correlation and investigation timelines, accessible keyboard-first operations, low-overhead shared sensors, policy simulation, signed rule packs, and explainable detection evidence. Each addition should preserve local control and avoid reducing coverage from Downpour's current feature set.
