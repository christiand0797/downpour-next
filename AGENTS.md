# Contributor and agent instructions

## Read before work

1. Read `SHARED_CONTEXT.md` for the current architecture and handoff state.
2. Read `WORK_QUEUE.json`; claim one task by setting it to `in_progress` and adding a short note before editing.
3. Read `SECURITY.md` and the relevant feature's source inventory entry.
4. Update `AGENT_REGISTRY.json` only while actively working; remove or mark the entry idle when handing off.

## Project rules

- This is a native Windows security product. Security, privacy, observable failure states, and least privilege take priority over breadth or polish.
- Do not claim parity for a route that is only a screen. Update its status only after its data path and acceptance criteria work.
- Keep contracts versioned and small. `Contracts` must not depend on WinUI or service infrastructure; `Core` owns reusable use cases; Windows API adapters stay in `Service`.
- Keep UI work on the dispatcher and all blocking collection, disk, feed, and scanning work off it.
- Default to read-only behavior. Never turn on process termination, quarantine, firewall changes, host isolation, hardening, or other system-changing actions without a distinct policy and auditable action broker.
- Do not run arbitrary command lines, shells, or downloaded content. Validate every path and parameter at the service boundary.
- Do not collect command lines, file contents, credentials, browser secrets, clipboard contents, or precise user activity unless a scoped feature explicitly requires it and a clear local consent flow is designed.
- Never check in credentials, signing keys, personal telemetry, machine-specific data, build output, or quarantine content.
- Keep NuGet dependencies version-pinned. Review dependency changes and GitHub Actions changes as security-sensitive code.
- Prefer documented Windows APIs, named contracts, bounded queues, structured logs, and explicit timeouts. No PowerShell subprocesses.
- Preserve the Python implementation as the behavior reference. Do not edit `C:\Users\purpl\Desktop\downpour_consolidated` during successor work unless the user explicitly asks.

## Work and handoff protocol

- Work only in this repository: `C:\Users\purpl\Desktop\downpour v2`.
- Keep `SHARED_CONTEXT.md`, `WORK_QUEUE.json`, `AGENT_REGISTRY.json`, and `TODO.md` current as work moves between milestones.
- Before pausing, record exact files changed, commit IDs, commands run and results, known failures, and the next safe task. Do not leave a claimed task without a handoff note.
- Use focused commits on `main` for this private repository. Push only changes from this directory to `https://github.com/christiand0797/downpour-next.git`.

## Build and verification

```powershell
dotnet restore Downpour.slnx
dotnet build Downpour.slnx -c Debug
dotnet test Downpour.slnx -c Debug
```

For an end-to-end local snapshot check, start `Downpour.Service` in one terminal and `Downpour.Desktop` in another. Stop both after the smoke check. Add tests for parsers, policy, and data transformations; privileged actions require dedicated denial, audit, timeout, and rollback tests before they can be enabled.
