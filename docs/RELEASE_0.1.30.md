# Downpour Next 0.1.30

Unsigned portable Windows x64 build. No installer, no service registration, no code signing, no telemetry.

## What changed since 0.1.29

### A quiet rule and a blind rule are no longer the same thing

An event-ID rule that cannot read its channel produces exactly the same result as a rule that is working and finding
nothing: no alerts. Until now the Alerts page could not tell those apart.

Every capture now records whether each of the seven allow-listed channels could be opened. The service stores that
readability (`alert_channel_health`) together with the moment coverage started watching (`alert_coverage`), and the alert
snapshot carries an `AlertRuleCoverageSummary` built by the existing `RuleCoverageMap`:

- **Rules**: the 35 built-in catalog rules (channel plus event ID).
- **CanFire / CannotFire / Silent / Unknown**: the four counts, which always add up to `Rules`.
- **Entries**: every rule that is not currently able to fire, with the channel, event ID and the reason, for example
  "Channel Security is not collected on this PC." or "Missing field(s) on System: …".
- **ObservedSinceUtc**: when readability was first recorded.

The Alerts page shows a `RULE COVERAGE · CAN THIS RULE FIRE HERE?` panel: how many built-in rules can fire here, which
cannot and why (up to four are named), and since when the store has been watching. When nothing is blocked the panel
says so instead of staying silent.

Silence is deliberately conservative. A zero match count is only reported as `Silent` after the store has observed for a
full 30-day window, so a fresh installation reports readable rules as able to fire rather than as quiet. Fire counts are
summed from stored occurrences, so re-reading the same event records never inflates them.

The desktop validates the new block strictly: the four counts must add up, the entry list is capped at 64, and every
field is bounded. An inconsistent or oversized block is rejected rather than displayed.

## Verification

- `dotnet build Downpour.slnx -c Debug`: 0 warnings, 0 errors.
- Full suite: **1,484 passed, 0 failed** (three new tests: a blocked channel is named, an unmeasured channel is never
  called silent, and contradictory or oversized coverage is rejected).
- Portable package: 1,077 entries, 772,425,528 bytes expanded.
- ZIP SHA-256 `4f80b4f5d4cbce2239fa28bdbd3b5ade6ca728a99e221727d3ca7ba771123b95` (306,423,711 bytes).
- SBOM SHA-256 `9102a7f340eb2a2218b5892d303c17e60cd2584f085cfa376120c665a3972068` (52 components).
- Packaged route smoke: every route opened with owned-service telemetry and closed gracefully without a new crash entry.
- Window smoke: native startup, maximize/restore, resize and owned-service shutdown passed.

## Not done / limits

- The coverage panel compiles and its tests pass, but it has not been inspected by hand; the route smoke opens the route
  without checking layout. The development machine's channel mix was not reviewed either, so the blind-spot wording has
  only been exercised by tests.
- Coverage covers the built-in event-ID catalog, not Sigma or Sysmon rules, whose catalogs are loaded per host.
- Readability is the last observed state per channel, not a history: the panel says a rule cannot fire now, not how long
  it has been blind.
- Unsigned build; no ARM64 package.
