# Follow-up foundations (started 2026-11-20)

Each of the fifteen ranked follow-ups now has a tested Core foundation. None is wired into a route or into the
service's behaviour yet: the table states what exists and what turning it into a feature still requires. This is the
same pattern as the 0.1.24 trust slice — tested building blocks first, honest status second.

| # | Follow-up | Foundation | Still needed to ship |
|---|-----------|------------|----------------------|
| 1 | Signed releases, fail-closed updater | `ReleaseTrustPolicy`, `tools/release/sign-release.ps1` (self-test passes) | Offline key custody, sign the packaged manifest, verify in `PortableUpdateInstaller`, signed-by UI line |
| 2 | Detection value per source/rule | `DetectionValueLedger` | Feed alert/FP outcomes into it from the service, show verdicts in Threat databases, demote control |
| 3 | Suppression lifecycle | `SuppressionPolicy` | Persist expiry/scope in the alert store, count hidden matches, surface warnings in Triage |
| 4 | Supply-chain self-check | `ComponentVulnerabilityMatcher` | Read the generated SBOM, feed NVD ranges in, add a gate to `tools/ci/run-gates.ps1` |
| 5 | Rule/catalog tamper-evidence, off-box anchor | `TrustedContentIntegrity`, `AuditAnchorPolicy` | Pin rule/catalog hashes in the manifest, verify at load, let the operator export an anchor |
| 6 | Durable change ledger | `ChangeLedger` | Write it from the persistence scan into protected state, add since-boot/day/week views |
| 7 | Durable alert provenance | `AlertProvenance`, `AlertProvenancePolicy` | Extend the alert record and migration, badge stale evidence in Triage and case export |
| 8 | Local diagnostics bundle | `DiagnosticsBundle` (redaction + bounds) | Collect service/pipe/feed states, preview-before-save dialog |
| 9 | Blind-spot diagnosis | `BlindSpotDiagnosis` | Aggregate the existing unavailable states from each sensor client into one screen |
| 10 | Operator metrics | `AlertOperationsMetrics` | Persist an acknowledgement timestamp (absent today) and show the panel |
| 11 | ARM64 scanner honesty | `ScannerArchitectureSupport` | An arm64 YARA-X module or the documented managed fallback, then the package |
| 12 | Least-privilege installed mode | `ServiceIdentityPolicy` | Dedicated service SID, pipe ACLs, audited privileged log read, installer/uninstaller |
| 13 | Offline rescue kit | `RescueKitPlan` | A kit manifest and read-only mode banner in the portable build |
| 14 | Refresh performance budgets | `RefreshBudget` | Instrument route refresh, record p95 in CI, expose quiet mode |
| 15 | Verifiable case packs | `CasePackRedaction`, `CasePackSignature` | Redaction preview in the export dialog, device/release signing key, recipient verification |

## Deliberate limits recorded in code

- Feeding value is judged only on reviewed outcomes and never auto-demotes a source.
- Suppressions gain an expiry and a warning when they hide a CRITICAL match; the existing permanent rule stays until
  the store migration lands.
- Provenance that was never recorded is `Unknown`, never `Current`.
- A bound-less advisory is treated as malformed rather than "affects every version".
- Blind-spot ranking drops ready checks; the rescue kit refuses any step that changes the system.
- The signing script refuses keys under RSA-3072 and never writes the private key anywhere.
