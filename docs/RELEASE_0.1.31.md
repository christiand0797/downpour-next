# Downpour Next 0.1.31

Unsigned portable Windows x64 build. No installer, no service registration, no code signing, no telemetry.

## What changed since 0.1.30

### Exploit mitigations are per image, and now visible

The Hardening page checks machine-wide settings: Secure Boot, VBS, Credential Guard, SMBv1, patch level. None of them
shows whether a browser was built with Control Flow Guard, whether a mail client still loads non-Microsoft DLLs, or
whether an editor allows dynamically generated executable memory. Those are per-image policies, and Windows exposes
them per running process.

The sensor now reads six controls for every running image with `GetProcessMitigationPolicy`:

- Control Flow Guard (CFG)
- Arbitrary Code Guard (ACG)
- Code Integrity Guard (CIG)
- Block non-Microsoft DLLs
- DEP
- ASLR

The Hardening route gains an `EXPLOIT MITIGATIONS BY PROCESS` panel: how many images were read, how many high-value
images (browsers, Office, mail, Teams, Slack, VS Code) are missing at least one control, how many processes refused the
query, and the six most exposed images with their score and the names of the missing controls.

### One row per image, not per process

Browsers and editors run many identical processes. The panel groups by image name, keeps the worst-scoring instance as
the representative, and shows how many instances were folded in (`chrome ×7`). High-value images are listed first, then
the lowest score.

### Refusal is not exposure

A process that will not answer the query — a service running as another account, a protected process, a process that
exits mid-scan — is counted in the refusal total and never reported as missing a mitigation. Only complete readings are
reported, and that matters technically: DEP requires a handle with `PROCESS_QUERY_INFORMATION`, while the other five
policies accept `PROCESS_QUERY_LIMITED_INFORMATION`. A limited handle returns `ERROR_ACCESS_DENIED` for DEP even for the
caller's own process, so a partial handle cannot produce an honest six-control row.

A real unelevated capture on the development machine read 40 images and refused 128, which is what a standard-user
desktop looks like: user applications answer, services and protected processes do not.

### Read-only

Processes are opened for query access only. Nothing is changed, no policy is applied, no command or PowerShell is run.
The score describes the policy Windows reports; it is not a malware verdict, and a control shown off may be disabled by
the vendor or unavailable on that Windows build.

## Verification

- `dotnet build Downpour.slnx -c Debug`: 0 warnings, 0 errors.
- Full suite: **1,490 passed, 0 failed** (six new tests: policy-bit mapping, worst-instance grouping, high-value
  ordering, snapshot validation bounds, a live unelevated capture, and a provider-to-pipe round trip).
- Release build: **1,490 passed, 0 failed**; all published executables report `0.1.31+4104b981…`.
- Portable package: 1,077 entries, 772,526,640 bytes expanded.
- ZIP SHA-256 `b48c46bcc6bffa49c7283c377ca45c2010565afc43ce564e60776819cc5c0947` (306,454,701 bytes).
- SBOM SHA-256 `32b4a97a044e9e0b7e0ef2e25d791e70a8ade46d34098e35a3cad0c849127fe2` (52 components).
- Packaged route smoke: every route opened with owned-service telemetry and closed gracefully without a new crash entry.
- Window smoke: native startup, maximize/restore, resize and owned-service shutdown passed.

## Not done / limits

- The mitigation panel compiles and its tests pass, but it has not been inspected by hand; the route smoke opens the
  route without checking layout. The six-row cap and the score colours have only been exercised in code.
- Remediation is guidance text. No mitigation is applied, and the panel does not route a fix into the existing fixer;
  changing per-image policy is a separate decision with reboot and compatibility effects.
- A refused process is counted, not listed: the panel cannot say which services refused, only how many.
- The reading is a snapshot of currently running images. A process started after the 15-second cache window appears on
  the next read; the BinarySignature "block non-Microsoft DLLs" bit is unavailable on older Windows builds and reads as
  off there.
- Unsigned build; no ARM64 package.
