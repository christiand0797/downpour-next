# Downpour Next v0.1.20

This release packages the latest hardening, driver/update, database and dashboard work, including the new administrator helper.

- 45 catalogued threat sources, including remote-access tool intelligence, with local matching and source status.
- 43 hardening checks and 35 catalogued fixes, recommended batches, backup/Undo, and Windows permission prompts for each elevated run.
- Windows Update software and driver installation through Windows Update Agent. No automatic restart; no promise that a compatible driver exists for every device.
- CVE dashboard connecting CISA known-exploited vulnerabilities with local evidence; Settings storage/cache controls; unsupported/unenrolled Insider warning.
- Release-review fixes: recovery journal persisted before each mutation, partial-mutation rollback, failed-rollback retention, protected-storage validation before error/watchdog writes, and accurate empty-update results.

Extract the entire Windows x64 ZIP and start Downpour.Desktop.exe or a bundled launcher. The package contains Desktop, Service, Scanner, UpdateHelper and Fixer; no separate .NET runtime is needed. Checksums, per-file manifest and CycloneDX runtime inventory accompany the package.

Validation: clean committed source `7af332e3ae35f224b30f016c3831386f1e5b1593`; Debug and Release each passed 1,196 tests, with zero build warnings/errors. Packaged startup/lifecycle smoke passed for Parental Controls, Dashboard, Threat Databases, Audio, Devices, Processes, Hardening, CVE and Settings; no new crash-log entries, and owned services stopped on close. YARA loaded 179 rules and the benign fixture had no matches. The fixer refused two invalid commands with exit 2 before storage/host changes; its packaged executable includes the administrator manifest.

No real privileged changes are executed as part of release smoke. This portable development build is unsigned; clean-machine and native elevated crash/reboot acceptance remain open. The local adaptive engine, further driver discovery and tree/sidebar visual work remain queued.

GitHub Actions run [37881112098](https://github.com/christiand0797/downpour-next/actions/runs/37881112098) could not start because the account is locked due to a billing issue; the validation above ran locally.

Archive verification: 1,077 entries, 305,525,710 compressed bytes, 769,965,623 expanded bytes. Every ZIP entry matches staging; the application's own integrity inspector also matched all 1,076 manifested files. CycloneDX inventory includes 52 runtime NuGet/native components, including the single-file helpers' embedded dependencies.

ZIP SHA-256: `f04d3b30bcbe415edbcd775a9e551f959be87167b1d41af0b2c116d519cc1a17`.

SBOM SHA-256: `1e8d4f874cc38ba22ead261dac89c6361ebbb609c4bb9f7532cde7a1ab455466`.
