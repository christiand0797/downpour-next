# Downpour Next 0.1.38

Portable Windows x64 build. Read-only security monitoring, local only, unsigned.

## Portable preferences

`PortableSettingsBundle` was the last tested Core shape with no producer. Settings → **Storage & cache** now has a
**Portable preferences** row with **Export…** and **Import…**.

Export writes one file, `Downpour-preferences-<date>.dpnb`, containing the eight local appearance and alert switches:

`RainEffectsEnabled`, `ReduceMotion`, `AutoStormCycle`, `NotificationsEnabled`, `MinimizeToTray`,
`SoundAlarmEnabled`, `SoundAlarmIncludesHigh`, `RansomwareContentSampling`.

The plaintext is a new bounded document (`downpour-preferences.v1`): 8 KiB, at most 32 entries, names of ASCII letters
only and booleans only. It is then encrypted with the existing bundle container — PBKDF2-SHA-256 at 210,000 iterations,
16-byte salt, AES-256-GCM with a 16-byte tag — using a passphrase the person types twice, at least 12 characters long.
Downpour does not store the passphrase and cannot recover it.

**What it refuses to carry.** Suppressions and selected cases are not exported: the alert store owns them, and importing
them elsewhere would hide matches on a PC where nobody made that review decision. Feed and lookup credentials are
refused by the preview and stay DPAPI-bound to the machine. The two setup acknowledgements stay behind, because they
mean "this person saw the explanation on this PC". No field exists that could hold a path, host name, account name or
free text, so nothing else can ride along under a switch's name.

**Import.** The file is size-checked, decrypted, and read against the known switch list. A wrong passphrase, a foreign
schema, an unknown or repeated name, a non-boolean value or an oversized payload refuses the whole document and says
"Nothing was changed" — an import is never partly applied. When it is valid, the confirmation lists every switch that
would change (`on → off`), and only then are the values applied. Storm cycling is re-armed from the imported value, the
Settings toggles are re-read with their handlers muted, and the window's visuals follow the existing preference event.

## Verification

- Debug build: 0 warnings, 0 errors. Full Debug suite: 1,538 passed, 0 failed (7 new in `PortablePreferencesTests`).
- Release build from `7f0a88a0c91822460f502e06ac314e767557e5b4`: 1,538 tests passed, five self-contained publishes;
  every executable reports `0.1.38+7f0a88a0c91822460f502e06ac314e767557e5b4`.
- Package: 1,077 entries, 772,829,702 expanded bytes, 52 runtime components.
- Packaged route smoke: every route opened, the sensor pipe answered, the YARA helper loaded 179 rules and the benign
  fixture produced no match, no new crash entry; the owned desktop, service and scanner stopped.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore and resize, CIS startup and owned-service
  shutdown passed.

## Digests

| Asset | Bytes | SHA-256 |
|---|---|---|
| `DownpourNext-win-x64-0.1.38.zip` | 306,576,286 | `04761b06e04689a133e88c30fc4019c4a041ee3faf5b390e6643f1bbe1d189a0` |
| `DownpourNext-0.1.38-sbom.cdx.json` | 26,237 | `f1f26bc6229f6d7ac98fdfc90a1c0857c988df92cc81c5cf25255c74a607bdbb` |
| `DownpourNext-0.1.38-SHA256SUMS.txt` | 198 | `fa2d6964f4103c23706d1dc0ec7b28eb0374eca12f4a2e076cd900169ea59d0a` |

## Limits

- The **Export…/Import…** buttons, the passphrase dialog and the file pickers were not clicked by hand. No bundle was
  exported and re-imported on a second Windows account or a second PC; the core document and container are unit-tested,
  the dialog wiring is compiled only.
- A bundle carries switches only. Suppressions and cases need a service-side export path and a decision about carrying
  someone else's review decisions.
- The passphrase cannot be recovered or rotated, and the destination folder is wherever the person saves the file;
  Downpour does not restrict or scan it.
- With every second-round foundation now wired, the remaining blocked work is unchanged: egress byte volume (ETW or
  administrator ESTATS), metered feed scheduling (no documented session-0 signal), ARM64 (no arm64 YARA-X module),
  release signing (offline key custody) and hosted CI (billing).
- A real in-app update exercising the staging journal and locked-file rollback failure injection are still open.
- The binaries are unsigned. A GitHub digest proves the file you downloaded is the file that was uploaded; it does not
  prove who built it.
