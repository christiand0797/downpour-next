# DNS novelty: first sighting on this PC

## What was wrong

The resolver-cache route already had a TOFU baseline, but it was a `HashSet` saved with `known.Take(20_000)`. Once a PC had
more than 20,000 remembered names, each capture wrote an **arbitrary** subset: a name still sitting in the resolver cache
could fall out of the baseline, be called new on the next capture, and raise the same DGA finding again — and again on the
next cycle. The baseline never converged, and nothing recorded *when* a name was first seen, so the page could not say
whether a name was new today or new three months ago.

## What it does now

`DomainBaseline` (Core) is a bounded, deterministic memory keyed by SHA-256:

- **Two dates per hash**, first seen and last seen. No name is stored — the file remains useless as a browsing history.
- **Least-recently-resolved eviction.** At capacity the name with the oldest last-seen date leaves first, ties broken by
  hash. A name resolved in today's cache therefore survives while space is contested, and repeating a capture reports
  nothing new. This is the regression the old `Take(n)` could not avoid.
- **First capture is a baseline.** It is written and reports `FirstRun`; the caller stays silent and entries carry no
  first-seen date, because claiming "first seen now" for an entire machine would be false.
- **Invalid hashes are ignored**, duplicate hashes count once, and the "name is new" answer never repeats for a name the
  baseline still holds.

The provider (`DnsInventoryProvider`) reads both file shapes: the current `{SchemaVersion:2, Domains:[{Hash, FirstSeenUtc,
LastSeenUtc}]}` and the earlier list of hashes or plaintext names, which are hashed and stamped with the file's own time —
known *at least since* then, which is what the evidence supports. A stored date in the future is clamped to now so it cannot
win every eviction comparison forever.

`DnsCacheSnapshot` now reports `NewlyObservedCount`, `ObservedSinceUtc` (the earliest remembered name) and `BaselineCount`,
and every entry carries an optional `FirstSeenUtc`. The DNS page's status line says how many names were resolved here for
the first time and since when, with the limit spelled out: *a first sighting on this PC, not the domain's registration age*.
When eviction happens the snapshot says how many names left and why.

## What it does not claim

- This is **local novelty**. A name can be years old and still be new to this PC; the reverse is also true after a
  baseline reset or eviction. It is not a newly-registered-domain feed, and it is not evidence of maliciousness.
- Clearing *Learned baselines* in Cleanup makes every name new again by design; the page then reports the first capture
  rather than pretending nothing changed.
- Findings still require a DGA score at or above `DgaDetector.AlertThreshold`. A new but ordinary name is context only.

## Verification

- Debug build 0 warnings / 0 errors; **1,557 tests pass** (5 new in `DomainBaselineTests`).
- The eviction test fills the baseline to its minimum capacity, resolves the oldest name again, adds one new name, and
  asserts the least-recently-resolved name left, the new name stayed, the re-resolved name stayed, and a repeat capture
  reported zero new names.
- `DnsBaselinePrivacyTests` now also asserts the v2 file still contains no plaintext name, only hashes and the two dates.
- The DNS page status line, and a real baseline above 20,000 names, were **not** viewed on screen.
