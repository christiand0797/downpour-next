# Bundled YARA rules: provenance

- **Source:** Downpour v29 (`downpour_consolidated/yara_rules/`, version 29.0.0, 2026-04-27), written for that project. 33 rule files, 179 rules.
- **Imported:** 2026-10-07 for DN-026. `../yara_rules.sha256` lists each file's SHA-256 as bundled.
- **Engine:** YARA-X 1.21.0 C API (see `../Downpour.Scanner.csproj` for the pinned release, commit, and hashes). Includes are disabled; files are compiled one by one so a broken file is reported in the Scanner screen instead of disabling all rules.

## Changes from v29

YARA-X rejects patterns that a rule declares but never uses in its condition (error E022). v29 hid these failures with a lenient compile, so 10 files never loaded there. In this copy, each such pattern is renamed with a `$_` prefix, which YARA-X accepts as intentionally unused. **No condition, string value, or rule logic was changed**, so every rule matches exactly what v29 intended; the renamed patterns were never evaluated.

| File | Patterns renamed |
|---|---|
| byovd_attacks.yar | 2 |
| credential_dumpers.yar | 1 |
| dll_hijacking.yar | 3 |
| dll_sideload_injection.yar | 3 |
| fileless_malware.yar | 6 |
| infostealer_2026.yar | 2 |
| iot_botnets.yar | 12 |
| webshell_backdoor.yar | 1 |
| wiper_malware.yar | 6 |
| wmi_persistence.yar | 2 |

To review: diff each file against the v29 original; every changed line differs only by `$name` → `$_name`.
