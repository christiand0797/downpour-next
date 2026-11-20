# Downpour Next 0.1.27

Unsigned portable Windows x64 build. No installer, no service registration, no code signing, no telemetry.

## What changed since 0.1.26

### Service and driver cross-view consistency

- The services inventory enumerates the Service Control Manager and the `Services` registry key independently and
  compares them. When 1–10 entries exist in only one view, it adds a bounded warning naming up to three of them, worded
  as a consistency anomaly and never as proof of tampering. More than 10 differences is treated as a view mismatch and
  stays silent.
- The driver inventory does the same for running driver services: on Windows builds that hide kernel module addresses
  from standard accounts, the WMI running-driver list is checked against the registry driver keys, and running drivers
  with no key raise the same advisory warning.
- Both checks were quiet on the development machine (182 running drivers, all with registry keys), so neither produces
  noise when the two views agree.

### Desktop crash fixed

The packaged route smoke caught a real crash: a pipe worker can close before writing a payload, and
`NetworkInventoryClient` let the resulting `InvalidDataException` escape into an `async void` refresh timer, terminating
the desktop while the Network route was open. The network, driver and installed-software pipe clients now treat an empty
or oversized frame exactly like every other pipe failure: no snapshot. The crash was confirmed in the desktop crash log
and the same route then passed.

### Smoke harness

The 0.1.27 packaged route smoke waits for the owned service (up to 30 s), for the main window handle, and up to 20 s for
graceful exit, with a 10 s snapshot read deadline. These are timeouts only: every assertion about routes, owned services,
snapshots, graceful close and crash logs is unchanged and still enforced. The earlier 3 s/8 s limits failed on a loaded
machine without any route being broken.

## Verification

- `dotnet build Downpour.slnx -c Release` and the full Release suite: **1,479 passed, 0 failed**.
- Portable package: 1,077 entries, 736 MB expanded.
- Packaged route smoke: every route started with owned-service telemetry, graceful close stopped the owned service, no
  new crash log entry, YARA helper loaded 179 rules and scanned a benign fixture without matches.
- Window smoke: native startup, maximize/restore, resize and owned-service shutdown passed.
- ZIP SHA-256 `8e72a8a8674f652b9d3e79bc32eb12ac9276447c345c6759748f4b6a441e6a66` (306,378,613 bytes).
- SBOM SHA-256 `c6a0cc1d2acb634e76d9355279b5aaec80e92a199a90ef7322d296479791eb9b`.

## Not done / limits

- The Alerts explanation panel from 0.1.26 has still not been inspected by hand; the route smoke does not click it.
- Egress byte-volume baselining remains blocked (ETW or admin-only ESTATS); metered feed scheduling needs runtime proof
  of a session-0 cost API before it can be wired.
- Unsigned build; no ARM64 package.
- The service and driver cross-view warnings are advisory and only cover the SCM/registry and running-driver/registry
  view pairs; ports and loaded-module name matching remain unwired.
