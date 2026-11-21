# Downpour Next 0.1.35

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## First-run guidance on the Dashboard

A new install is legitimately quiet: feeds download, the alert store starts watching, and nothing has gone wrong yet.
The screens were honest about that but read as "it does not work", which is exactly when people uninstall. The Core
onboarding plan could compute the next step; nothing used it.

The Dashboard now shows one **Setup** card under the sensor status card:

- **Feeds** — advances when at least one feed holds entries. If the feed service answered, no feed holds entries and at
  least one failed, the card says the first download did not finish and calls it a real failure rather than the expected
  quiet start.
- **Baseline** — advances after the alert store has been watching for 24 hours. A missing or future observation start
  never counts.
- **Permissions** — explains that administrator access is what lets Downpour read the security log and autostart
  locations, with a **Got it** acknowledgement.
- **First days** — explains what a quiet first week looks like, with the same acknowledgement.
- **Ready** — the card hides.

`OnboardingPlan.StateFrom` is a pure derivation from facts the dashboard already holds, so the order and every refusal
are unit-tested. An unanswered feed service is treated as the startup case, not a failure, and the feed facts are
re-read at most once a minute with a transient miss keeping the previous answer, so the card never walks backwards.

The acknowledgements record that the person **saw** the explanation. They are not a claim that administrator access
exists, and the card cannot grant it: no elevation prompt, no scheduled task, no service registration, no firewall
change. Only the two booleans are stored, in the existing preferences file.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,517 passed, 0 failed (9 new in `OnboardingStateTests`).
- Release build from `34956daa404ac88bf1b63b3851ab3ff14f06311b`: 1,517 tests passed, five self-contained publishes.
- Package: 1,077 entries, 772,687,146 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, no new crash entry.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.35.zip` | 306,526,378 | `d0a69223acad86881b694a67bc351fb76db9117f2b82bd22c4eae554b6e8f73e` |
| `DownpourNext-0.1.35-sbom.cdx.json` | — | `20529888fa3cdab02b51375b42ce626bb2b7333dddedd35f6816a8e0fe3717f6` |
| `DownpourNext-0.1.35-SHA256SUMS.txt` | — | `0dbec4d09bb188acb3184406b2e8b0a12915e41eb96c57f312b79c46b4c17121` |

## Limits

- The Setup card has not been viewed at any width, and the first-run sequence has not been walked on a fresh store.
  This machine is past its 24-hour observation window, so it would show the permission or quiet-period step.
- The failed-download branch is proved by the derivation tests only, not against a real broken feed.
- The baseline signal is the alert store's observation window, not the local-learning engine. The card does not claim
  more than "the store has been watching".
- The binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not
  prove who built it.
- A real in-app update exercising the update staging journal and locked-file rollback failure injection are still open.
