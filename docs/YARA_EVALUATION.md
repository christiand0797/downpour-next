# YARA dependency evaluation (DN-026)

**Status:** proposal for owner review. No YARA dependency has been added. The owner decided: "evaluate and propose" (SECURITY.md, 2026-10-07).

**Why YARA:** v29 scanned files with `yara_x_engine.py` (YARA-X, with a lenient compile and a yara-python fallback) over the 34 rule files in `yara_rules/`. The Scanner route in Downpour Next does PE metadata and hashing only.

## Options

| Option | Engine | .NET support | Maintenance | License | Native code we would ship |
|---|---|---|---|---|---|
| **A. YARA-X C API with our own P/Invoke** | YARA-X (Rust), the engine v29 used | None official. We write a small P/Invoke layer. | Active. VirusTotal runs it in production and calls it "mature and stable". | BSD-3-Clause | `yara_x_capi.dll`, built from a pinned tag with `cargo-c`. Releases do not ship the C library. |
| B. dnYara + libyara 4.x | Classic YARA (C) | netstandard2.0, P/Invoke | Wrapper last released 2.1.0 in Jan 2022. Classic YARA receives fixes only; YARA-X is its successor. | Apache-2.0 wrapper; BSD-3 libyara | `libyara.dll`, which we would still have to build. The wrapper also pulls in `Mono.Posix.NETStandard`. |
| C. libyara.NET | Classic YARA | .NET Framework 4.5–4.8 only (C++/CLI) | Last release 3.5.2 in 2017 | (see repo) | Not usable on .NET 10 |
| D. Run `yr.exe` / `yara64.exe` as a subprocess | Either | n/a | n/a | BSD-3 | Executables. **Rejected:** AGENTS.md forbids subprocess command execution in the product. |

## Recommendation: Option A, YARA-X through a minimal C API binding, scanning in an isolated helper process

1. **Same engine as v29.** Rule semantics match what v29 shipped. Classic YARA is in maintenance mode.
2. **Small, auditable surface.** The binding needs about ten functions: `yrx_compiler_create`/`add_source`/`build`, `yrx_rules_destroy`, `yrx_scanner_create`, `yrx_scanner_set_timeout`, `yrx_scanner_scan`, the matching-rules iterator, and the destroy functions. This avoids an unmaintained wrapper plus an extra Mono dependency.
3. **Supply chain.**
   - Build `yara_x_capi.dll` in CI from a pinned YARA-X release tag (commit hash recorded).
   - Pin the Rust toolchain and `cargo-c` versions.
   - Record the DLL's SHA-256 in the repo and verify it at load.
   - Sign it with the same Authenticode certificate as Downpour releases once signing exists (DN-010).
   - Generate an SBOM entry.
   - Never download it at runtime.
4. **Isolation.** A native parser runs over untrusted files, so a crash or memory-safety bug must not take down the sensor service. Scanning runs in a separate `Downpour.Scanner.exe`:
   - A job object caps memory, CPU time, and child processes.
   - A low-integrity token where feasible.
   - Bounded IPC.
   - The service restarts it on failure.
   - YARA-X is written in Rust, which reduces but does not remove this risk.
5. **Rules.**
   - Bundle v29's `yara_rules/*.yar` with their provenance.
   - Compile them at build time in CI, so syntax errors fail the build rather than the user's scan.
   - Record which v29 rules YARA-X rejects. v29 needed a "lenient compile", so some will fail.
   - Per-scan timeout of 10 s per file, a file size cap of 256 MiB (matching the inspector), and no automatic quarantine.

## Acceptance criteria if approved

- The binding has unit tests for compile errors, matches, no match, timeout, and empty or oversized input.
- The CI job builds the DLL reproducibly, and its hash matches the committed value.
- The helper process survives a crashing rule or input: the service reports "scanner unavailable" and does not crash.
- The Scanner route offers recursive scanning with bounds, cancellation, and progress, and reports matches as findings in triage.
- A report shows which v29 rules load. Rules that fail are listed, not hidden.

## Effort and owner decisions needed

- About 2–3 working sessions: binding and tests, the CI build, the helper process, and the UI.
- **Decision 1:** approve adding a Rust-built native DLL to the release (Option A).
- **Decision 2:** confirm the isolated helper-process design, which adds one executable to the package.

Sources: YARA-X C API docs (virustotal.github.io/yara-x/docs/api/c/c-), the YARA-X repository (BSD-3-Clause), and the NuGet pages for dnYara 2.1.0 and libyara.NET 3.5.2.
