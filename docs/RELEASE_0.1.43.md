# Downpour Next 0.1.43

The DNS route has always learned which names this PC resolves, but it could not say *when* it first saw one — and once that
memory filled up it saved an arbitrary subset, so a name could drop out and raise the same finding again. 0.1.43 replaces
that memory with a bounded, deterministic one and puts first sighting on the screen.

## First sighting on this PC

- `DomainBaseline` (Core) remembers **SHA-256 hashes plus two dates** — first seen and most recently seen. No domain name
  is written, so the file on disk is still not a browsing history.
- At capacity it evicts the **least recently resolved** name (ties broken by hash), not an arbitrary subset. A name in
  today's resolver cache therefore survives while space is contested, and repeating the same capture reports nothing new.
  This is the defect the old `Take(20_000)` caused: the same DGA-like name could alert, fall out, and alert again.
- The first capture is still a **baseline**: it is written, nothing is called new, and entries carry no first-seen date.
- An old baseline file (list of hashes, or the older plaintext names) is migrated in place; legacy entries are stamped with
  the file's own time, because "known at least since then" is all the evidence supports.
- The DNS page now states how many names were resolved here for the first time and since when, and spells out the limit:
  **a first sighting on this PC, not the domain's registration age.** When the baseline is full, the snapshot says how many
  names left and why.
- New contract fields: `DnsCacheSnapshot.NewlyObservedCount`, `ObservedSinceUtc`, `BaselineCount`, and an optional
  `DnsCacheEntry.FirstSeenUtc`. Every one is bounded by the desktop client, and a first-seen date later than its capture is
  rejected.

## Why this rather than a newly-registered-domain feed

The stronger external signal (names first seen today in certificate transparency, e.g. SANS ISC `domaindata.json.gz`) is
still blocked on CC BY-NC-SA terms, so it was not wired. This slice is what can be built honestly from local observation:
it answers "has this PC ever resolved this before, and when", which is a real question an investigator asks, without
pretending to know a domain's age.

## Verification

- Debug build: 0 warnings, 0 errors. **1,557 tests pass** (5 new in `DomainBaselineTests`).
- The eviction regression is pinned: the oldest last-seen name leaves, a re-resolved name and the new name stay, and a
  repeated capture reports zero new names.
- `DnsBaselinePrivacyTests` asserts the v2 file contains hashes and dates only, with no plaintext domain-shaped string.
- Packaged route smoke (every route, 179 YARA rules) and window smoke passed.
- **Not viewed:** the DNS page status line, and the over-capacity path on a real machine.

## Limits

- Local novelty is not reputation, registration age or proof of anything. A name can be new here and perfectly ordinary.
- Clearing *Learned baselines* legitimately makes every name new again; the page then reports the first capture.
- Findings still require a DGA score at or above the alert threshold; a new but ordinary name is context only.
