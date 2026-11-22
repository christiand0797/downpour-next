# Portable preferences

Settings → Storage &amp; cache → **Portable preferences** moves the appearance and alert switches to another PC as one
passphrase-encrypted file. This is the call site for `PortableSettingsBundle` (DN-084), the last Core foundation from the
second round that had no route.

## What may leave the machine, and what may not

A bundle carries **eight switches only**, by name:

| Bundle name | What it controls |
|---|---|
| `RainEffectsEnabled` | Rain animation on the Dashboard |
| `ReduceMotion` | Reduced-motion rendering |
| `AutoStormCycle` | Automatic storm-mode cycling |
| `NotificationsEnabled` | Alert toasts |
| `MinimizeToTray` | Closing to the tray |
| `SoundAlarmEnabled` | The sound alarm |
| `SoundAlarmIncludesHigh` | Whether HIGH alerts also sound the alarm |
| `RansomwareContentSampling` | Content sampling in ransomware review |

Everything else is excluded on purpose:

- **Suppressions** are not exported. They are review decisions tied to this store; importing them elsewhere would hide
  matches on a PC where nobody made that decision. The service also owns that table, so a desktop-side export could not
  read or write it without a new privileged path.
- **Cases and investigation content** are never exported. The Core preview still offers the `IncludeCases` option for a
  future signed case-pack path, but this build never asks for it; a preferences bundle cannot carry evidence.
- **Feed and lookup credentials** are refused by `PortableSettingsBundle.Preview` and live in DPAPI-bound storage. They
  are deliberately re-entered on the new PC.
- **The two setup acknowledgements** (`setupPermissionsSeen`, `setupQuietPeriodSeen`) are excluded. They mean "this person
  saw the explanation on this PC", which is not true on the PC the bundle is carried to; carrying them would let the
  Dashboard skip a step nobody read.
- **Machine and account detail** cannot be carried even by accident: the document accepts only short ASCII letter names
  and booleans, so there is no field that could hold a path, host name, user name or address.

## Format

`PortablePreferences.Serialize` writes a bounded JSON document, names sorted ordinally so the same switches always
produce the same plaintext:

```json
{"schema":"downpour-preferences.v1","values":{"RainEffectsEnabled":true,"ReduceMotion":false}}
```

Bounds: 8 KiB, 32 entries, 64-character names, letters only, booleans only. `PortableSettingsBundle.Encrypt` then wraps
it in the `DPNB1` container: 16-byte salt, 12-byte nonce, 16-byte tag, PBKDF2-SHA-256 at 210,000 iterations, AES-256-GCM
with the magic as associated data. A passphrase must be at least 12 characters.

## Flow

**Export**: file picker → passphrase dialog (typed twice) → encrypt → write. The success message states that Downpour
does not store the passphrase and that it cannot be recovered.

**Import**: file picker → size check (64 KiB) → passphrase dialog → decrypt → `PortablePreferences.Deserialize` against
`AppPreferences.PortableNames` → `DescribeChanges` → confirmation listing each switch that would change (`on → off`) →
apply. Every failure says "Nothing was changed", and the reader refuses a document **whole** — an unknown name, a
non-boolean value, a repeated name, a wrong schema or an oversized payload never results in a partly applied import.

After a confirmed import the Settings toggles are re-read with their handlers muted, storm cycling is re-armed from the
imported value, and the window's visual preferences update through the existing `AppPreferences.Changed` event.

## Verification

- Debug solution build: 0 warnings, 0 errors.
- `PortablePreferencesTests` (7 tests): round trip through encrypt/decrypt, wrong-passphrase rejection, unknown-name
  refusal naming the field, name/size/count/empty refusals on write, malformed/duplicate/non-boolean/oversized refusals
  on read, change summary listing only differences, a payload-shape check that no backslash, `@` or free text can appear,
  and the preview's content/refusal lists.
- Total Debug suite result for this slice is recorded in `SHARED_CONTEXT.md`.

## Not verified

- The two buttons and the passphrase dialog were not clicked by hand, and no bundle was exported and re-imported on a
  second Windows account or PC. The flow is compiled and its core logic is unit-tested; the dialog wiring is not.
- The file picker writes wherever the person chooses. Downpour does not scan or restrict that folder, and a bundle copied
  into a synced folder leaves the machine by the person's own choice.
- There is no passphrase recovery and no key rotation. A bundle is a static encrypted file.
