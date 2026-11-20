# Downpour Next 0.1.28

Unsigned portable Windows x64 build. No installer, no service registration, no code signing, no telemetry.

## What changed since 0.1.27

### Listening ports on the Network page

The service snapshot now carries a bounded list of up to 64 TCP listeners (`Listeners`, `TotalListenerCount` on
`NetworkInventorySnapshot`), each with local endpoint, address scope and port. The Network page shows them in a
`LISTENING PORTS` section and counts how many appeared after the page was opened, so a port that shows up while you are
watching is visible without a diff. The list is read-only and has no process attribution: it says a socket is listening,
not which program owns it.

### New remote destinations

The connections footnote now digests remote endpoints first seen since the page opened. The baseline is seeded from the
first successful snapshot, so endpoints that already existed are never labelled new. Both counters live in memory for the
lifetime of the page instance; nothing is persisted and reopening the page starts a fresh baseline.

## Verification

- `dotnet build Downpour.slnx -c Release` and the full Release suite: **1,479 passed, 0 failed**.
- Portable package: 1,077 entries, 736 MB expanded.
- Packaged route smoke: every route started with owned-service telemetry, graceful close stopped the owned service, no
  new crash log entry, YARA helper loaded 179 rules and scanned a benign fixture without matches.
- Window smoke: native startup, maximize/restore, resize and owned-service shutdown passed.
- ZIP SHA-256 (recorded below), SBOM SHA-256 (recorded below).

## Not done / limits

- The new Network sections have not been inspected by hand; the route smoke opens the route but does not check layout.
- Listener inventory covers TCP only and does not attribute process owners or expose TCP states other than listening.
- Destination and listener digests are per page instance and are not persisted across restarts.
- The Alerts explanation panel from 0.1.26 still has not been inspected by hand.
- Egress byte-volume baselining remains blocked (ETW or admin-only ESTATS); metered feed scheduling needs runtime proof
  of a session-0 cost API before it can be wired.
- Unsigned build; no ARM64 package.
