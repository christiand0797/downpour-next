# Downpour Next 0.1.36

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## TCP listener cross-view

The Network capture reads two independent enumerations of the same listening sockets: the managed
`GetActiveTcpListeners()` list (IPv4 and IPv6 — 44 + 10 on this machine) and the native
`GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)` table that already supplies process attribution. Both key on
`IPEndPoint.ToString()`, so a difference is a real difference in the enumeration rather than a formatting mismatch.

A listener present in one view and not the other is now reported:

- One to ten one-sided endpoints produce one warning naming at most three:
  `N TCP listener(s) appear in only one of the managed and native tables: …`.
- More than ten are silent. Listener churn on a busy machine is normal, and a long warning would be noise.
- Either table empty is silent: an unreadable table proves nothing about the other.
- The warning always ends by saying the tables are read a moment apart, so a listener that started or stopped in
  between can differ, and that this is a **consistency anomaly, not proof of tampering**. A socket accepted between the
  two reads produces exactly this difference.

Read-only: no table, socket, process or file is changed, and nothing is persisted. The warning joins the existing
Network warnings list.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,522 passed, 0 failed (5 new in `NetworkInventoryProviderTests`).
- Release build from `7d1d83d9efc958d14faddc0999cc37a156743937`: 1,522 tests passed, five self-contained publishes.
- Package: 1,077 entries, 772,689,082 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, no new crash entry.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.36.zip` | 306,526,663 | `3b679a9d4b1d35dd22b5f879234efcbe1e871a94544b2853eb382dfad56ccb7a` |
| `DownpourNext-0.1.36-sbom.cdx.json` | — | `803638f875cbffe162cc5b15a5976437bd005e268380769a113800536fac4e88` |
| `DownpourNext-0.1.36-SHA256SUMS.txt` | — | `6f0d7983c7e2587b86646cabb63a8b04c864992c5997a5e0e666f63f82597e11` |

## Limits

- Whether this development machine's two views actually disagreed was not inspected, and the warning has not been
  viewed on the Network page at any width. The live capture asserts only that any listener warning it emits contains the
  non-tampering wording.
- The check compares enumerations, not ownership: a listener present in both views with a wrong owning process is not
  detected here.
- The binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not
  prove who built it.
- A real in-app update exercising the update staging journal and locked-file rollback failure injection are still open.
