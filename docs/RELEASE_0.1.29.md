# Downpour Next 0.1.29

Unsigned portable Windows x64 build. No installer, no service registration, no code signing, no telemetry.

## What changed since 0.1.28

### Listening ports name their owning process

0.1.28 added a read-only list of TCP listeners but could only say that a socket was listening. The service now resolves
each listener's owner from the Windows TCP owner tables (`GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_LISTENER`) for
both IPv4 and IPv6, using the same table snapshot rather than a per-port query. Each entry carries two optional fields,
`OwningProcessId` and `ProcessName`, and the Network page shows a `PROCESS` column.

- Image-name lookups are capped at 128 per snapshot; listeners beyond that keep their pid and leave the name blank.
- A name is never reported without a pid, and the client rejects a non-positive pid or a name with no pid.
- When the owning process cannot be opened (protected or exited), the pid is still shown and the name stays empty. The
  page does not guess a name from a partial match.
- The owner is captured at inventory time; a pid can be reused after the process exits, so the column is evidence of
  ownership at capture, not a live handle.

The inventory remains read-only, covers TCP listeners only, and does not expose non-listening TCP states.

## Verification

- `dotnet build Downpour.slnx -c Release` and the full Release suite: **1,481 passed, 0 failed** (two new tests: a real
  loopback listener maps to the test process id, and the cached image name matches the running executable).
- Portable package: 1,077 entries, 736.4 MB expanded.
- Packaged route smoke: every route opened with owned-service telemetry and closed gracefully without a new crash entry.
- Window smoke: native startup, maximize/restore, resize and owned-service shutdown passed.
- ZIP SHA-256 `024c39022bd6f2db5314c0b9cdb2e186589885b5b6d6d6f6dc8e4d7c75338bf7` (306,402,053 bytes).
- SBOM SHA-256 `ebee0668caeecea99ad2f79239c1b319476c0d4c27fec7951afd4b4931305793`.

## Not done / limits

- The PROCESS column and the 0.1.28 Network listener/destination sections have not been inspected by hand; the route
  smoke opens the route but does not check layout or column rendering.
- Listener attribution uses the OS owner tables only; it does not include byte counters or per-connection ETW data.
- Egress byte-volume baselining remains blocked (ETW or admin-only ESTATS); metered feed scheduling needs runtime proof
  of a session-0 cost API before it can be wired.
- Unsigned build; no ARM64 package.
