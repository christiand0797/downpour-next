# Downpour Next 0.1.32

Windows x64 portable development release. No runtime behaviour changed in this build: it adds the offline alert replay
gate that release verification now runs, and keeps everything shipped in 0.1.31.

- Source: `408fe2fb2b33db12913a5707ad21bfb3745de2a2` (binaries report `0.1.32+408fe2fb2b33db12913a5707ad21bfb3745de2a2`; the tag points at the following docs commit).
- Archive: 1,077 entries, 772,599,206 expanded bytes, 306,482,886 bytes zipped.
- ZIP SHA-256: `b88d9df3a3cd04c63082a86fc943c7d4051346ab16f23cf5136c56aadd62ca7c`
- SBOM (CycloneDX, 52 runtime components) SHA-256: `11fd7b8c707d7a41e6cc81d9a66c6b79560c8e9a5c9d6c6056fa963677a323b8`
- SHA256SUMS SHA-256: `18d890de4c4f21a7b84bd5b95419b4059a5cf9967cdca21fddca74c3f16cb164`

## What changed

- **Alert replay gate (DN-072).** The alert store's event-to-alert identity moved into Core (`AlertProjection.DedupKey`),
  so the live upsert and an offline replay compute it with one implementation. `AlertReplayRunner` loads a synthetic
  corpus of 12 Windows event records and the 10 alerts the built-in rules grade them into, using only
  `SecurityEventCatalog`/`SysmonCatalog`: no event log, network, signature check or service pipe.
- The corpus covers record identity, the five-minute 4625 burst bucket, hourly rollups, Sysmon record plus event ticks,
  and the no-record fallback across System, Security, PowerShell, Sysmon and Defender rules. `AlertReplayDiff` reports a
  missing alert, an unexpected alert or a severity change.
- `tools/ci/run-gates.ps1` now runs `AlertReplayGateTests` as its own step and stops on any difference. A deliberately
  tampered expected severity made the gate exit 1; the restored corpus exited 0. The test also refuses unknown rules,
  malformed or oversized corpora, and scans the corpus for drive, UNC and profile paths, e-mail addresses and IPv4
  literals. Details: `docs/ALERT_REPLAY.md`.
- Everything shipped in 0.1.31 remains: per-process exploit mitigations on Hardening, rule coverage with blind-rule
  naming, listener process attribution, the 58-source feed catalog, suppressions, retention/clock warnings and the
  existing read-only inventory routes.

## Verification

- Clean committed Release build: 0 warnings, 0 errors.
- Release test suite: 1,495 passed, 0 failed (includes the 5 replay gate tests).
- Package script verified every executable's version and embedded source, the WinUI resource index, loose assets, the
  YARA-X native digest, the SBOM and every ZIP entry by SHA-256.
- Packaged route smoke: every route in `capabilities.json` started, received owned-service telemetry and closed
  gracefully; the YARA helper loaded 179 rules and the benign fixture produced no match.
- Window smoke: maximized startup, resize/minimize/maximize styles, Restore, resize while restored and CIS-owned
  service shutdown all passed. No Downpour desktop, service or scanner was left running.

## Known limits

- The replay corpus covers catalog grading and alert identity only; Sigma/AMSI matching, feed parsers and the
  service-install signature re-grade keep their own tests.
- Binaries and updater metadata remain unsigned. Clean-machine deployment, ARM64, elevated crash/reboot acceptance and
  GitHub-hosted CI (account billing) remain open.
