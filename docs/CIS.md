# Cognitive Immune System: measured review slice

The route now reviews actual validated alert, system and settings snapshots. Scripted detector pools, synthetic resistance/confidence scores, forecast controls, pretend deployed honeypots and swarm-model protection controls have been removed from the product and their unused model code/contracts deleted.

## Connected behavior

- Refreshes every 30 seconds while the page is open; unload cancels outstanding work and stops the timer.
- Counts returned alerts by Open state, HIGH/CRITICAL Open severity, user-verified active state, suppression and distinct observed techniques. Unknown data stays unknown. Counts cover at most the 512-row service window; total stored rows and truncation are stated separately.
- Shows source health and actual script-content/action policy settings. A permitted policy is not a running detector or a successful response. User verification is a review decision, not proof of malware.
- Shows up to 32 recent alerts and the existing carefully limited temporal correlations. No common actor/campaign is inferred.
- Copies a bounded local review report only on request, including metadata, warnings, scope and any completed package-integrity findings. File contents are excluded.

## Explicit package integrity check

The button reads this installation's `release-manifest.json` and compares listed files against SHA-256/size entries. It validates schema 1, current three-part application version, source-commit shape, exact property sets, case-insensitive path uniqueness, required desktop/service entries, hashes and cumulative byte limits before opening any listed file. It rejects traversal, absolute/ADS paths, reserved Windows names, update-state paths, self-reference and detected reparse points.

Bounds: 1 MiB manifest, 2,000 entries, 256 MiB per file, 1 GiB total and a 30-second cancellation deadline. Reads/hash work runs off the UI dispatcher; file handles deny concurrent writes/deletes while held. Missing, unreadable, size/hash differences, absent/invalid manifests, timeout and cancellation are distinct outcomes. Cancellation never leaves a completed successful result. No file is changed or uploaded.

This local baseline is unsigned and can be replaced by the same user. Matching means consistency with that baseline, not publisher authenticity, malware clearance or continuous protection. Extra files and user state are outside the check. Path/link checks are not an installed privileged-service security boundary and do not establish resistance to same-user races/tampering. A source build without a release manifest reports unavailable instead of generating a self-approved baseline.

Regression coverage exercises real file bytes, same-size tampering, missing files, size mismatch, malformed/duplicate/extra fields, path traversal/ADS/reserved aliases, wrong version, resource budgets, cancellation, and linked directories/manifests. Link fixtures explicitly skip on hosts lacking Windows Developer Mode/SeCreateSymbolicLinkPrivilege; the supported local host executed them. Assessment tests cover offline/stale/forged data, truncation, state/verification semantics and bounded ordering.

This is a functional review/integrity slice. Continuous aggregate baseline learning and explainable recommendations are now implemented as described below. Validated adversarial evaluation, operational deception, semantic/process/memory baselines and complete v29 CIS parity remain unfinished. No admin operation or automatic response is added.

## Local learning, v0.1.21

A service worker polls the existing aggregate telemetry and current alert window independently of the visible page. It stores seven days of observed five-minute averages (CPU %, memory %, TCP connection count and process count), one sample per minute. A metric needs 24 completed buckets before being judged. Its baseline is the median; unusual means above median + max(a practical floor, 4 × 1.4826 × MAD). Floors are 10 percentage points CPU, 5 points memory, 15 connections and 25 processes. The current bucket never trains its own threshold. Missing intervals/metrics remain unknown; old state expires and duplicated minutes are ignored. Resource workload changes can be legitimate; this model is not a malware classifier.

CIS displays the current measurement, baseline, threshold, observed bucket count, last observation and source/storage warnings. Recommendations link to existing investigative routes. Correlation requires recent open HIGH/CRITICAL alerts alongside unusual connections, explicitly described as temporal co-occurrence without a causal claim. Model learning pauses through Settings; existing aggregates are retained only within the retention window. Storage uses bounded strict JSON, same-user ACLs and atomic replacement. Failed writes and corrupt files are visible; successful persistence survives restart. No API, LLM, new private content collection or autonomous fixes are used.
