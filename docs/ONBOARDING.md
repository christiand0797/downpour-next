# First-run guidance

A new install is legitimately quiet: feeds download, the store starts watching, and nothing has gone wrong yet. The
existing screens are honest but read as "it does not work", which is when people uninstall. `OnboardingPlan` computed
the next step since DN-052, but nothing used it. Since 0.1.35 the Dashboard does.

## The card

A single **Setup** card sits under the sensor status card and disappears once setup is complete. It shows one step at a
time with the plan's own headline and detail text:

| Step | Source of the fact | Action |
|---|---|---|
| Download feeds | `ThreatDatabaseService` snapshot: at least one feed holds entries | none — the card advances by itself |
| Establish baseline | `SecurityAlertSnapshot.Coverage.ObservedSinceUtc` at least 24 h ago | none |
| Confirm permissions | the person has seen the explanation | **Got it** |
| Explain the quiet start | the person has seen the explanation | **Got it** |
| Ready | all of the above | card hides |

The step label says `SETUP · FEEDS`, `SETUP · BASELINE`, `SETUP · PERMISSIONS`, `SETUP · FIRST DAYS` or
`SETUP · FEEDS BLOCKED` when the feed service answered, no feed holds entries and at least one failed.

## Derivation rules

`OnboardingPlan.StateFrom` is a pure function, so the order is testable without a service:

- An **unanswered** feed service is not a failure. It is the startup case, and the card simply stays on the download
  step.
- `FirstFeedDownloadFailed` requires an answer, zero feeds with entries, and at least one failed feed. That produces the
  plan's "this is a real failure, not the expected quiet start" copy instead of friendly text over a broken download.
- `BaselineComplete` requires an observation start in the past **and** at least 24 h of it. A missing start or a future
  timestamp never counts.
- `PermissionsConfirmed` and `QuietPeriodExplained` are local acknowledgements (`setupPermissionsSeen`,
  `setupQuietPeriodSeen` in `AppPreferences`). They record that the person has **seen** the explanation. They are not a
  claim that administrator access exists, and the card cannot grant it.
- Negative counts are rejected rather than silently clamped.

The feed facts are re-read at most once a minute and a transient miss keeps the previous answer, so the card never walks
backwards while the service is busy loading.

## What it does not do

- No automatic elevation request, no scheduled task, no service registration, no firewall change.
- It does not hide failures behind friendly copy: the failed-download branch is worded as a failure and carries
  `Blocking = false`, because nothing else waits on it.
- The baseline signal is the alert store's observation window, not the local-learning engine or a persistence baseline.
  The card copy is the plan's existing wording; it does not claim more than "the store has been watching".
- It does not persist any feed content or host data; only the two booleans live in the existing preferences store.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,517 passed, 0 failed (9 new in `OnboardingStateTests`).
- Not checked by hand: the card has not been viewed at any width, and the first-run sequence has not been walked on a
  fresh store. The development machine is long past its observation window, so it would show the permission or quiet
  period step rather than the feed step.
- Not exercised: the failed-download branch against a real broken feed; only the derivation is unit-tested.
