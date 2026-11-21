# Weekly summary

A local Markdown file, one per ISO week, written from counts the alert store already keeps. No email, no telemetry, no
network call, and no data the store does not already hold.

## Where and when

- Path: `%LOCALAPPDATA%\DownpourNext\reports\weekly-<ISO year>-W<week>.md`, for example `weekly-2026-W47.md`. The ISO year
  can differ from the calendar year around New Year.
- The service checks at start + 2 minutes and then every 6 hours. If this week's file is absent and the store has
  watched a full week, it writes one and leaves it alone for the rest of the week.
- This is a start-time plus six-hour check, not a midnight timer. A session that runs for months still gets the file at
  the next check; a machine that was off gets it when it starts. It is not "Monday 00:00".
- The reports folder is created under the existing per-user data root with the same restricted ACL as other local state;
  the file is written to a temporary name and moved into place, so a crash cannot leave a half-written report.
- The folder is not user-selectable. Settings (`Storage & cache` → **Weekly summary**) opens it; when it does not exist
  yet the page says so instead of opening an empty path.

## What it reports

From `SecurityAlertRepository.ReadWeeklyDigestFactsAsync`, one SQL aggregate per fact:

| Fact | Source |
|---|---|
| Alerts first seen / last seen in the window | `alerts.first_seen_utc`, `last_seen_utc` |
| Open now and the age of the oldest open finding | `alerts.state`, `first_seen_utc` |
| Acknowledged this week | `alert_state_events.next_state='Acknowledged'` |
| Suppressed this week | `alert_state_events.next_state='Suppressed'` |
| Active suppressions and matches they hid | `alert_fp_rules.suppressed`, `matches_since_grant` |
| Suppressions that expired this week | `alert_fp_rules.expires_at_utc` within the window |
| Evidence evicted this week | `alert_evictions` |
| Sensors that cannot read their source | existing rule-coverage query |
| Most active rule | `alerts.title`, ordered by occurrences in the window |

## What it refuses to claim

- **New autostarts**: no weekly autostart history is stored, so the digest prints "Autostart changes are not recorded by
  this build" under **Not recorded** rather than a zero that reads like a finding of absence.
- **Resolved findings**: the alert store has no `Resolved` state. Suppressed and acknowledged are reported separately;
  nothing is called resolved.
- **A quiet week**: the sentence only appears when the autostart, hidden-match and sensor counts are all known and zero.
  If any is unknown, the digest shows the changes it does know and the rest under **Not recorded**.
- **A short week**: no file is written until channel readability has been recorded for at least seven days, so a fresh
  install is not described as a quiet week after two days. No measurement at all means readability is unknown, not zero.

The digest caps at 40 lines and 32 KiB; an oversized report is refused rather than truncated, and the writer never
overwrites another week's file.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,531 passed, 0 failed (10 new in `WeeklyDigestTests`).
- Covered by tests: unknown inputs never produce the quiet-week sentence, the **Not recorded** section, acknowledgements
  versus resolution, backwards-window refusal, ISO week/ISO year naming (`2026-W47`, `2021-01-01` → `2020-W53`), mapping
  that never invents autostarts or resolutions, store aggregates against a temporary database including a window that
  opens after the row was stored, the seven-day deferral, and atomic bounded writing with overwrite inside one week.
- The packaged 0.1.37 service run created `%LOCALAPPDATA%\DownpourNext\reports` and left it empty, which is the
  seven-day gate observed rather than assumed.
- Not checked by hand: no report has been produced on this machine, because its alert store has been watching for less
  than seven days. The file content, the reports-folder button, and the rendered Settings row were not viewed.
