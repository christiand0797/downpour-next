# Downpour Next 0.1.40

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## Retention that says what it counts

The alert store keeps 10,000 alerts for 30 days and drops whatever does not fit. The retention summary already said how
many alerts were evicted in the last seven days — but the warning text never mentioned evictions, because the read
computed the total one way and then handed an empty list to the code that writes the warnings:

```csharp
var evicted = /* SQL SUM over alert_evictions */;
var report = StoreRetentionAccounting.Assess(retained, capacity, oldest, now, window, []);  // <- empty
return new AlertRetentionSummary(..., evicted, report.Warnings…);                            // number right, sentence missing
```

The read now selects the per-day rows for the window, builds `RetentionDay` records and passes them to `Assess`. The
number and the sentence come from one computation, so the store cannot count evictions and stay silent about them.
Unparseable days are skipped instead of failing the whole snapshot, and negative counts are clamped.

## Retention where storage is managed

Settings → **Storage & cache** gains an **Alert history** row:

- retained of capacity, over the retention window;
- the oldest retained alert;
- the seven-day eviction total;
- the store's own warnings, appended, with the line turning amber when there are any;
- a **Refresh** button, and an explicit "alert history is unavailable while the sensor service is offline" state
  instead of zeros that would read as "nothing was evicted".

Read-only. Nothing is pruned, extended or reconfigured from this row.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,545 passed, 0 failed (1 new test).
- `RetentionSaysOutLoudWhatItsEvictionCountShows` inserts five evictions for today directly into `alert_evictions` and
  asserts both `Retention.EvictedLast7Days == 5` and that the warnings contain the eviction sentence with the number —
  the exact pair that used to disagree.
- Release build from `b2e28abe8d889c32fdfe54e13b9ecc4257ad9543`: 1,545 tests passed, five self-contained publishes;
  every executable reports `0.1.40+b2e28abe8d889c32fdfe54e13b9ecc4257ad9543`.
- Package: 1,077 entries, 772,879,714 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, no new crash entry; the owned desktop, service and scanner stopped.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.40.zip` | 306,598,917 | `ec0b2ab88cbd75f76888873835b9a3e112996a254087df7e5050a1e753a67d14` |
| `DownpourNext-0.1.40-sbom.cdx.json` | 26,237 | `44411b79a8b40c4b3d1248cffa3d5128ba32ebad770b7eb14034cb543048059e` |
| `DownpourNext-0.1.40-SHA256SUMS.txt` | 198 | `0488cadce001c4e568da5a3bea7b225a496ff839d8e1ee0c4bc2c7df15cfad81` |

## Limits

- **The Alert history row was not viewed.** It is compiled and its read path is tested; the amber warning state and the
  service-offline wording have not been seen. This machine's store is far below capacity and has no evictions, so the
  eviction sentence will not appear here without a synthetic store.
- Evictions are recorded per UTC day with no reason attached: the summary can say how many, not which alerts, and the
  capacity warning is inferred from the retained count and the age of the oldest alert.
- Retention stays 10,000 alerts / 30 days. Nothing here changes the policy.
- A real in-app update over an installed build is still not exercised; the locked-file rollback path is covered by unit
  tests only.
- Binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not prove
  who built it.
