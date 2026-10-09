# Downpour Next v0.1.20

This release packages the latest hardening, driver/update, database and dashboard work, including the new administrator helper.

- 45 catalogued threat sources, including remote-access tool intelligence, with local matching and source status.
- 43 hardening checks and 35 catalogued fixes, recommended batches, backup/Undo, and Windows permission prompts for each elevated run.
- Windows Update software and driver installation through Windows Update Agent. No automatic restart; no promise that a compatible driver exists for every device.
- CVE dashboard connecting CISA known-exploited vulnerabilities with local evidence; Settings storage/cache controls; unsupported/unenrolled Insider warning.
- Release-review fixes: recovery journal persisted before each mutation, partial-mutation rollback, failed-rollback retention, protected-storage validation before error/watchdog writes, and accurate empty-update results.

Extract the entire Windows x64 ZIP and start Downpour.Desktop.exe or a bundled launcher. The package contains Desktop, Service, Scanner, UpdateHelper and Fixer; no separate .NET runtime is needed. Checksums, per-file manifest and CycloneDX runtime inventory accompany the package.

Validation and artifact digests will be recorded after the clean committed build and packaged smoke checks. No real privileged changes are executed as part of release smoke. This portable development build is unsigned; clean-machine and native elevated crash/reboot acceptance remain open. The local adaptive engine, further driver discovery and tree/sidebar visual work remain queued.
