# Downpour Next v0.1.21

Downpour now starts maximized on every launch and keeps normal Windows restore, resize and minimize controls.

The new local learning engine runs with the sensor service, independently of the visible page. It learns observed CPU, memory, connection-count and process-count baselines without an API or LLM. Seven days of five-minute aggregates stay on this PC in bounded protected storage. CIS shows current readings, normal values, thresholds, maturity and explanations, with links to investigate unusual resources or connections alongside recent urgent findings. Settings can pause learning and recommendations. It performs no automatic fixes.

Each metric needs 24 completed observed buckets (at least two hours) before judging deviations. Missing time remains unknown, brief outliers have limited influence, and a new reading cannot train away its own anomaly. Correlation is temporal context, not proof of causation or malware. Threat Pulse also now reports learning for empty history instead of inventing days of quiet observations.

Debug build: zero warnings/errors, 1,218 tests passed. Clean Release and packaged verification pending. Windows x64 portable development release; unsigned. Learning requires the service to be running, and the portable service closes with the app. Full semantic agent behavior, universal driver discovery, visual improvements, signing and clean-machine acceptance remain queued.
