# Agent handoff: v29 reanalysis and parity work

**Written:** 2026-10-06 by `claude-parity-audit` (DN-015, completed)
**For:** the next agent instructed to "reanalyze all files", and any agent that picks up parity work after it.

Read `AGENTS.md` first. Its rules still apply: read-only by default, no system-changing actions without the DN-008 broker, no PowerShell subprocesses, version-pinned NuGet, and never edit `C:\Users\purpl\Desktop\downpour_consolidated`.

## 1. State you are inheriting

- All work that was uncommitted on 2026-10-06 (Sigma, Sysmon, AMSI, quarantine/action broker stubs, NVD, URLhaus/Abuse.ch, driver packages, timeline page, performance changes) is now committed and pushed to `origin/main`. It was committed as-is from agents that ran out of usage. It builds and passes tests, but it has **not had a code review**. Treat it as unreviewed.
- `dotnet build Downpour.slnx -c Debug --no-incremental`: 0 warnings, 0 errors. `dotnet test`: 191 passed.
- `AGENT_REGISTRY.json` was invalid JSON. It is repaired. Agents that were left "active" are now marked idle.
- No live agent sessions remain. You are the only agent working. Still claim tasks in `WORK_QUEUE.json` before you edit.

## 2. The reanalysis is mostly done: verify and extend it, don't redo it

These artifacts already exist:

| File | Contents |
|---|---|
| `docs/V29_PARITY_AUDIT.md` | Screen-by-screen gap matrix, non-screen features, inventory corrections, process issues |
| `parity-checklist.json` | 205 v29 workflows across all 38 routes, plus 22 non-route features. The parity gate for each route. |
| `source-modules.json` | 129 entries: every wired v29 module, dead-in-v29 modules marked `orphaned`, and content directories |

The audit came from static extraction: tab builders, `command=` handlers, threads, `after()` loops, and a transitive import graph. It did **not** capture the following. Do these as your reanalysis, in this order:

1. **Verify the import graph.** Look for dynamic loading the regex could miss (`importlib`, `__import__`, `exec`, string-built module names, plugin folders such as `revolutionary_enhancements/` and `ultimate_threat_intel/`). If an `orphaned` module is in fact loaded, change it back to `planned` and say why in its description.
2. **Settings and config.** List every key in v29 `config.json`, `config.py`, and the `ConfigManager` class, with its default and what reads it. Add the result to `parity-checklist.json` as a `settings` section.
3. **Thresholds and detection constants.** For each `planned` detection module, record the scoring thresholds, IOC lists, and event IDs it uses, so ports reproduce v29 behavior. Use fixture-style notes in `docs/` and keep one file per module family.
4. **Data stores.** List v29's on-disk stores (`downpour_data/`, `downpour_v27_data/`, SQLite DBs, JSON caches, `models/`) and their schemas. Decide which ones Downpour Next must migrate or import.
5. **Right-click and context-menu actions.** The audit only caught `command=` handlers. Grep for `tk.Menu` / `add_command` per tab and add any missing workflows to the checklist.

Update `docs/V29_PARITY_AUDIT.md` and `parity-checklist.json` in place. Do not create parallel inventories.

## 3. Then take implementation tasks from `WORK_QUEUE.json`

Suggested order. Every one of these is read-only:

1. **DN-016**: fix driver signature verification. It currently runs `WinVerifyTrust` against `.inf` files, which are catalog-signed, so legitimate drivers show as failed. This is a misleading security state, so fix it first.
2. **DN-017**: load the v29 `sigma_rules/*.yml` files. `LoadFromYamlFiles` exists but has no callers.
3. **DN-018**: hardening and firmware posture. **DN-019**: firewall view and Event 5157.
4. **DN-023**: Threats / Possible Threats / false-positive store.
5. DN-020, DN-021, DN-022, DN-024, DN-025, DN-026, DN-027 as capacity allows.
6. **DN-009** stays the umbrella task for the large routes: AEGIS, CIS, forensics, sandbox, memory, ransomware, parental, cleanup, VPN, remote access, IoT, emergency.

Do **not** enable kill, quarantine, block IP, firewall edits, USB block, revert-all, lockdown or driver changes. DN-008 needs a security review, plus denial, audit, timeout and rollback tests, before any of those.

## 4. Review items found in the unreviewed code

- `DriverPackageInventoryProvider.VerifyDriverSignature`: wrong trust model for INFs (DN-016). The signer extraction uses obsolete `CreateFromSignedFile` behind a scoped pragma.
- `Downpour.Service.csproj` pins `System.Management` 9.0.0 while the other Microsoft packages are 10.0.12. Check whether WMI is needed at all, since AGENTS.md prefers documented Win32 APIs, and align the version or remove it.
- `ThreatIntelligencePage` and the Abuse.ch/URLhaus clients fetch public feeds. Confirm they meet the same bounds as `KevCatalogClient`: fixed hosts, no redirects, size and time limits, and strict parsing.
- `SigmaAmsiPushWorker` and `AmsiIntegration`: confirm script-block content is never persisted or exported. AGENTS.md forbids collecting command lines or file contents without a consent flow.

## 5. Before you stop

Follow AGENTS.md's handoff protocol: update `SHARED_CONTEXT.md`, `WORK_QUEUE.json`, `AGENT_REGISTRY.json` and `TODO.md`; record the commands you ran and their results; commit in focused commits and push to `origin/main`.
