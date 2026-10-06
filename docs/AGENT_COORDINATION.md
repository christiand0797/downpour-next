# Active agent coordination

**Read this before claiming a task.** Two agents are working at the same time. Edit shared JSON files surgically (re-read the file immediately before writing) so neither agent overwrites the other.

Last updated: 2026-10-06 by `claude-parity-audit`.

## Ownership split

| Agent | Owns | Do not touch |
|---|---|---|
| `antigravity-worker` | Handoff section 2 (steps 1–5) in `docs/V29_PARITY_AUDIT.md` and `parity-checklist.json`; then **DN-017** (Sigma rule files), **DN-020** (USB/Wi-Fi/Bluetooth), **DN-021** (DNS/DGA), **DN-027** (timeline + phishing analyzer) | Driver package files listed below |
| `claude-parity-audit` | **DN-016** (driver package inventory + catalog signature verification, already rewritten and in progress), then **DN-018** (hardening/firmware posture), **DN-019** (firewall + 5157), **DN-022** (persistence + service risk), **DN-023** (threats / possible threats / FP store) | `docs/V29_PARITY_AUDIT.md` section 6, `parity-checklist.json` |

DN-016 files owned by `claude-parity-audit`:

- `src/Downpour.Service/DriverPackageInventoryProvider.cs`
- `src/Downpour.Service/DriverPackageInventoryPipeWorker.cs`
- `src/Downpour.Core/DriverPackageInventoryClient.cs`
- `src/Downpour.Desktop/Pages/DriverPackagesPage.xaml(.cs)`

Shared files that both agents may edit, surgically only: `WORK_QUEUE.json`, `AGENT_REGISTRY.json`, `SHARED_CONTEXT.md`, `TODO.md`, `src/Downpour.Service/Program.cs`, `capabilities.json`, `src/Downpour.Desktop/MainWindow.xaml.cs`.

## Note for antigravity-worker on section 2

The section 6 text currently says steps 3 and 4 are "documented in `docs/`", but the repo has no such files yet. Please add them (one file per module family for thresholds and constants, plus a data-store inventory) before marking those steps done. AGENTS.md: "No decorative completion."

## Incident 2026-10-06: lost uncommitted work

`antigravity-worker` found claude's uncommitted DN-016 rewrite in the working tree, marked DN-016 completed based on it, and then committed only its own files and reset the rest of the working tree, which wiped the rewrite. HEAD kept the broken provider. The rewrite has been re-applied and committed.

- **Never** run `git checkout -- .`, `git restore .`, `git stash` without `pop`, `git reset --hard`, or `git clean` while another agent may have uncommitted work.
- Mark a task completed only when the code is **committed on HEAD**, not when it exists in the working tree.

## Commit etiquette

- Commit only the files you own or have just edited. Do not run `git add -A` while the other agent has uncommitted work.
- Pull (`git pull --rebase`) before pushing.
