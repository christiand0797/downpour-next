# Alert retention, visible

The alert store keeps 10,000 alerts for 30 days and silently drops whatever does not fit. `StoreRetentionAccounting`
turns that into facts: what is retained, against what capacity, how old the oldest alert is, and how many were evicted in
the last seven days. This slice fixes a place where those facts disagreed with each other and shows them where storage
is managed.

## The bug

`SecurityAlertRepository.ReadRetentionAsync` read the seven-day eviction total with one SQL `SUM`, then called
`StoreRetentionAccounting.Assess(..., evictions: [])` — an empty list. So:

- `AlertRetentionSummary.EvictedLast7Days` was correct, and
- `AlertRetentionSummary.Warnings` never contained the `N alert(s) were evicted in the last seven days.` sentence,
  because that sentence is produced from the list that was passed as empty.

The Alerts warning panel therefore showed capacity warnings but stayed silent when evidence had actually been evicted,
even though the number was sitting in the same record. Two computations of one fact, one of them empty.

## The fix

The read now selects the per-day rows (`SELECT day,evicted FROM alert_evictions WHERE day >= …`) into
`RetentionDay` records and passes them to `Assess`. The summary's number and its warnings now come from one computation,
so the store cannot report evictions without also saying so in words. Rows are bounded by the seven-day window the read
already used, unparseable days are skipped rather than throwing, and negative counts are clamped.

## Where it is shown

Settings → **Storage & cache** gains an **Alert history** row:

`312 of 10,000 alerts kept over 30 days · oldest 2026-11-04 19:12 · none evicted in 7 days.`

When evictions exist it says `N evicted in 7 days`, appends the store's warnings, and turns amber. When the sensor
service is not running it says so instead of showing zeros, and the **Refresh** button re-reads it. Read-only: nothing
is pruned, extended or reconfigured from this row.

## Verification

- `RetentionSaysOutLoudWhatItsEvictionCountShows` inserts five evictions for today directly into `alert_evictions`, then
  asserts the snapshot's `Retention.EvictedLast7Days` is 5 **and** its warnings contain the eviction sentence with the
  number. That is exactly the pair that used to disagree.
- Debug build: 0 warnings, 0 errors. `SecurityAlertRepositoryTests`: 18 passed. Full Debug suite result is recorded in
  `SHARED_CONTEXT.md`.
- **Not checked by hand:** the Settings row has not been viewed at any width, and this machine's store may have no
  evictions at all (retained counts are far below capacity), so the amber path is unit-tested only. The row's
  "service offline" wording is also unviewed.

## Limits

- Evictions are recorded per UTC day with no reason attached; the summary can say how many, not which alerts.
- The store does not record *why* an alert was evicted (age versus capacity). The warning infers capacity pressure from
  the retained count and the age of the oldest alert, which is why it needs a nearly full store before it speaks.
- Retention remains 10,000 alerts / 30 days; nothing here changes the policy or offers to.
