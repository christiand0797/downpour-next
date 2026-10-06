# Action Broker Design

## Overview

The action broker is a critical security component that enforces explicit authorization, audit logging, and safe execution of system-changing actions. It implements a default-deny policy: no action executes unless explicitly authorized by policy and user consent.

## Architecture

```
Desktop UI
    │
    │ 1. User initiates action (e.g., quarantine file)
    │
    ▼
Action Policy Validator
    │
    │ 2. Validates against:
    │    - Action catalog (allow-list)
    │    - Feature switches (default-off)
    │    - Explicit consent for non-dry-run requests
    │    - Policy version
    │    - Object ID format
    │    - Required parameters
    │
    ▼
Action Preview Generator
    │
    │ 3. Generates preview for user consent:
    │    - Expected effects
    │    - Risks
    │    - Rollback steps
    │
    ▼
Desktop UI (Consent Dialog)
    │
    │ 4. A future UI records explicit user consent
    │
    ▼
Quarantine Manager (Service, preparation only)
    │
    │ 5. Prepares operation:
    │    - Validates file path
    │    - Computes SHA-256 hash
    │    - Records intent in journal
    │
    ▼
Operation Journal
    │
    │ 6. Records:
    │    - Operation ID
    │    - Operation kind
    │    - State transitions
    │    - Result codes
    │
    ▼
Quarantine Manager (Service)
    │
    │ 7. Current entry point rejects execution; no file or journal mutation occurs
    │
    ▼
Desktop UI
    │
    │ 8. Shows result
```

## Components

### 1. Action Contracts (`Downpour.Contracts/ActionBroker.cs`)

Versioned contracts for action requests and responses:

- `ActionRequest`: Proposed action request with action kind, object ID, policy version, dry-run flag, parameters, and a consent signal
- `ActionResponse`: Result with acceptance status, result code, operation ID, and details
- `ActionCatalogEntry`: Metadata for an action kind (display name, description, category, required parameters)
- `ActionCatalogSnapshot`: Versioned catalog of all available actions
- `ActionPolicyValidation`: Validation result with violations and warnings
- `ActionPreview`: Preview of effects, risks, and rollback steps for user consent
- `FeatureSwitch`: Feature toggle configuration (default-disabled)
- `UserConsentGiven`: Explicit consent signal required for non-dry-run validation; it is not authenticated operator evidence by itself

### 2. Action Catalog (`Downpour.Core/ActionCatalog.cs`)

Default action catalog with versioned policy definitions:

- Schema version: 1
- Policy version: 1.0.0
- Actions: `QuarantineFile`, `RestoreFile` (more to be added)
- All actions are disabled by default
- Each action has: display name, description, category, required parameters, allowed object ID patterns

### 3. Feature Switch Manager (`Downpour.Core/FeatureSwitchManager.cs`)

Manages feature switch state with local persistence:

- Storage: `%LOCALAPPDATA%\DownpourNext\feature-switches.json`
- Schema version: 1
- All features start disabled
- Policy version changes auto-disable features
- Thread-safe with semaphore gate; reads fail closed to catalog defaults for corrupt or incompatible persisted state
- Updates hold the gate across a private read-modify-write path, avoiding recursive acquisition

### 4. Action Policy Validator (`Downpour.Core/ActionPolicyValidator.cs`)

Validates action requests against policy constraints:

- Checks schema version
- Validates action kind is in allow-list catalog
- Checks feature switch is enabled (default-deny)
- Validates policy version matches current
- Validates required parameters are present
- Validates object ID format (`obj-` + 32 hex chars)
- Validates object ID matches allowed patterns
- Requires explicit consent and a non-empty operator SID for non-dry-run requests; preview generation validates policy before consent
- Operator SID is only an asserted contract field today; a future service endpoint must bind it to the authenticated IPC caller
- Generates preview for user consent dialogs

### 5. Quarantine Manager (`Downpour.Service/QuarantineManager.cs`)

Preparation foundation only:

- Prepares a quarantine request: validates file metadata, computes hash, records intent in journal
- Does not move, replace, encrypt, or delete files; no quarantine execution path is wired
- Path validation: no traversal, absolute paths only, no reserved device names
- File size limit: 256 MiB
- Hash verification: SHA-256 must match expected hash
- Journal integration: records preparation intent only
- The execute entry point rejects as unimplemented; no journal state transition is made

### 6. Operation Journal (`Downpour.Service/OperationJournal.cs`)

Existing journal foundation:

- SQLite with WAL mode, foreign keys, synchronous=FULL
- Schema version 2
- Records: operations (projection) and operation_events (append-only history)
- State machine supports Prepared → ContentStaged → Quarantined (or RestorePrepared → Restored), but current broker code only records Prepared intent
- Recovery states: RecoveryRequired, Failed
- Enforces legal transitions
- No action execution: records intent only

## Security Guarantees

### Default-Deny
- All actions are disabled by default via feature switches
- No action execution path is currently wired; feature switches default off
- Policy version changes auto-disable features

### Explicit Authorization
- Non-dry-run validation requires a consent signal and an operator SID
- No consent UI or authenticated action endpoint exists yet
- Preview generation describes intended effects, risks, and rollback steps without executing anything
- Dry-run mode available for preview/testing

### Bounded Preparation
- File size limit: 256 MiB
- Path length limit: 260 characters
- No execution timeout or cancellation is implemented because actions are not executable
- Parameter validation occurs before journal preparation

### Audit Trail
- Prepared operations are recorded in journal
- Append-only event history (SQLite triggers prevent updates/deletes)
- Result codes for all outcomes
- State transitions are atomic

### Crash Recovery
- Journal records intent before execution
- Failed/RecoveryRequired states remain visible
- Recovery requires explicit typed verifier (not yet implemented)
- No automatic resume on startup

### Path Safety
- No directory traversal (`..` check)
- Absolute paths only
- No reserved device names (CON, PRN, etc.)
- Hash verification before action

## Current Limitations

1. **Quarantine execution does not exist**: `QuarantineManager` rejects execution without touching the file or advancing the journal. `QuarantineStorage` is an unintegrated draft and is not reachable from an action endpoint.
2. **No restore implementation**: RestoreFile action catalog entry exists but not implemented
3. **No recovery verifier**: RecoveryRequired state cannot be resolved
4. **No integrated encrypted storage**: `QuarantineStorage` remains an unintegrated draft; no action endpoint can reach it
5. **No UI integration**: No UI pages for consent dialogs or action management
6. **No authenticated consent**: User SID is collected but not bound to authenticated IPC identity

## Next Steps

1. Design and verify quarantine execution before implementing file mutation; keep the current entry point rejecting requests
2. Implement restore action with hash verification
3. Implement recovery verifier for RecoveryRequired state
4. Add UI consent dialog integration
5. Add UI page for feature switch management
6. Add UI page for operation history and recovery
7. Add process termination, network blocking, and host isolation actions (after quarantine/restore is verified)

## Testing

Focused tests:
- `ActionPolicyValidatorTests`: 12 tests for request policy, explicit consent, switches, parameters, object IDs, dry-run, and preview generation
- `FeatureSwitchManagerTests`: 8 tests for defaults, enable/disable, persistence, schema mismatch, corrupt state, and policy-version changes
- `QuarantineManagerTests`: verifies preparation validation and that the unsupported execution path leaves the original file and journal state unchanged

Focused Release tests pass 26/26; the full Release suite passes 144/144. The previous `SetEnabledAsync` stall came from recursively acquiring the same semaphore through `LoadAsync`; updates now use a lock-held private loader.

## References

- `docs/ACTION_JOURNAL.md`: Operation journal foundation
- `docs/SECURITY_MODEL.md`: Security model and threat areas
- `src/Downpour.Contracts/ActionBroker.cs`: Action contracts
- `src/Downpour.Core/ActionCatalog.cs`: Default catalog
- `src/Downpour.Core/FeatureSwitchManager.cs`: Feature switches
- `src/Downpour.Core/ActionPolicyValidator.cs`: Policy validation
- `src/Downpour.Service/QuarantineManager.cs`: Quarantine implementation
- `src/Downpour.Service/OperationJournal.cs`: Journal foundation
