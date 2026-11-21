# TCP listener cross-view

`CrossViewInventory` already compared the SCM against the `Services` registry key, and the driver list against driver
keys. The port views were the last unwired pair. Since 0.1.36 the Network capture compares the two independent
enumerations of the same listening sockets:

- **Managed view**: `IPGlobalProperties.GetActiveTcpListeners()`, which returns both IPv4 and IPv6 listeners (44 + 10
  on this machine at the time of writing).
- **Native view**: `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)` for both address families, the same table that
  already supplies process attribution.

Both use `IPEndPoint.ToString()` for the key, so a difference is a real difference in the enumeration, not a formatting
mismatch.

## Rules

- **Nothing on one side only** → no warning. Both views agree.
- **One to ten one-sided endpoints** → one bounded warning naming at most three: `N TCP listener(s) appear in only one
  of the managed and native tables: …`.
- **More than ten** → silent. Listener churn on a busy machine is normal, and a twelve-endpoint warning would be noise,
  not evidence.
- **Either table empty** → silent, because an unreadable table proves nothing about the other one.
- Endpoint comparison is case-insensitive and bounded at `CrossViewInventory.MaximumArtifacts`.

## What the wording claims

The warning always ends with: *"The tables are read a moment apart, so a listener that started or stopped in between can
differ; treat it as a consistency anomaly, not proof of tampering."* That is deliberate. A socket accepted between the
two reads, or a listener whose process exits between them, produces exactly this difference. The check exists to make a
one-sided listener reviewable, not to assert that something is hidden from one view.

It is read-only: no table is modified, no socket is closed, no process is touched, and nothing is persisted.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,522 passed, 0 failed (5 new in `NetworkInventoryProviderTests`).
- Tests cover: identical sets agree, case-insensitive matching, a one-sided endpoint named with the non-tampering
  wording, silence when either table is empty, and silence above ten differences while ten still reports.
- The live capture also asserts that any listener warning it emits contains the non-tampering wording. Whether this
  development machine's two views actually disagreed was not inspected, and the warning has not been viewed on the
  Network page.
