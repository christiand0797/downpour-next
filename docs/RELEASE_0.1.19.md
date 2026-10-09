# Downpour Next v0.1.19

Host-isolation cleanup now reports failure if firewall rules cannot be removed or their absence cannot be verified. Failed rollback preserves scheduled recovery, recovery intent must be saved before applying rules, and the UI receives the actual isolation state. Turning off new isolation still permits a confirmed release. Scheduled cleanup failures return a failure status and request three one-minute retries.

The portable bundle now includes the HUD backdrop, moon image and tray icon. This release also carries the other agents' committed improvements since v0.1.18: Threat Pulse hourly baselines, tamper-evident audit records, deterministic parser fuzzing, and richer service-install/case-file evidence. Parental Controls' initialization crash fix and the 19-source database integration from v0.1.18 remain included.

Validation: clean committed Release build at `a672449615987e2b73da8042e3eb2d7db3ff2af5`, zero warnings/errors, 1,117 tests passed. Includes 18 host-isolation tests with failure injection; no real isolation was performed on the development PC. Packaged route/scanner verification and final archive evidence are recorded in the newest SHARED_CONTEXT checkpoint.

Windows x64 portable development release; extract the entire ZIP and run Downpour.Desktop.exe. SHA-256 checksums, a per-file integrity manifest and CycloneDX runtime dependency inventory are included. Builds are unsigned. Installed elevation/signing, native elevated failure/reboot recovery and full v29 parity remain unfinished. Scheduled recovery requires its registered executable to remain available. Parental Controls currently configures and reviews policy; it does not enforce access or measure usage.

Published package also includes the alert-client validation regression fix, laptop feed-error normalization and sensor resilience, Devices & Drivers, cross-view process checks, per-tab charts, and Kuro animation improvements. Six packaged routes and YARA helper smoke passed. Published ZIP SHA-256: `265c1c9c56d01bea5037341505660bc25fffcd5edb96db4be096c72e5c68cb5f`.
