# Downpour Next v0.1.21

Downpour now starts maximized on every launch and keeps normal Windows restore, resize and minimize controls.

The new local learning engine runs with the sensor service, independently of the visible page. It learns observed CPU, memory, connection-count and process-count baselines without an API or LLM. Seven days of five-minute aggregates stay on this PC in bounded protected storage. CIS shows current readings, normal values, thresholds, maturity and explanations, with links to investigate unusual resources or connections alongside recent urgent findings. Settings can pause learning and recommendations. It performs no automatic fixes.

Each metric needs 24 completed observed buckets (at least two hours) before judging deviations. Missing time remains unknown, brief outliers have limited influence, and a new reading cannot train away its own anomaly. Correlation is temporal context, not proof of causation or malware. Threat Pulse also now reports learning for empty history instead of inventing days of quiet observations.

Verified source: `80004fa48e41c8c93b518f5b0052fc159d6350fb`. Debug and clean Release: zero warnings/errors, 1,218 tests passed in each. Native checks confirmed maximized startup, normal window styles, Restore and resize without forced re-maximization. The service-only learning probe verified fresh data with no page open, pause across a worker interval, persisted settings/history after restart, and resume; original settings were restored. Ten packaged routes, owned-service shutdown and YARA (179 rules, benign fixture) passed. Downpour's integrity inspector matched all 1,076 manifested files.

ZIP: 305,608,999 bytes, 1,077 verified entries, 770,201,348 expanded bytes. SHA-256: `a660fd87efebb2e0819c0244c252138251c8f73347b574c20c2640bced34b84e`. CycloneDX inventory: 52 runtime components; SHA-256: `45a684e600543a6ba6081e436402ca933db50a87fbad2b8c7ebf4800b9112768`.

GitHub Actions run 37981012956 could not start because the account is locked due to billing; these checks ran locally. Windows x64 portable development release; unsigned. Learning requires the service to be running, and the portable service closes with the app. Full semantic agent behavior, universal driver discovery, visual improvements, signing and clean-machine acceptance remain queued.
