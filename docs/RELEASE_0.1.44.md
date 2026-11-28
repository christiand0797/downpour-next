# Downpour Next 0.1.44

The persistence sweep now answers a question it could not before: **which local accounts exist on this PC, and which of
them are administrators** — and it notices when that changes.

## Local accounts in the persistence baseline

- Every local user account is now an entry in the same trust-on-first-use baseline as Run keys, scheduled tasks, WMI
  subscriptions and drivers. The first sweep records what exists and calls nothing new.
- An account created afterwards is reported as new: `CRITICAL` when it is an enabled administrator, `HIGH` when it is
  an enabled standard user, `MEDIUM` when it is disabled. An existing account **added to Administrators** is reported as
  a modification with the same `CRITICAL` finding — the local half of T1136.001.
- The Persistence page's category filter includes the new category, and the account entries appear in the same list and
  change digest as everything else.
- Strictly read-only and unelevated: `NetUserEnum` and `NetUserGetLocalGroups` are ordinary queries. Nothing enables,
  disables or deletes an account.

## Two defects found while building it

Both were caught by a temporary harness before release, and both would have shipped as real faults:

1. **Duplicate accounts.** The first implementation paged `NetUserEnum` with a resume handle and appended whatever came
   back. It reported **256 accounts on a machine with eight** — duplicates filling the cap. It now makes a single call
   with `MAX_PREFERRED_LENGTH` and de-duplicates by name.
2. **A multi-minute stall in the service's capture path.** `NetLocalGroupGetMembers` at level 3 resolves every member
   name, including domain principals; on a machine whose domain controller is unreachable the call blocked until the
   harness timed out. Membership is now read per account with `NetUserGetLocalGroups`, which resolves only local group
   names, and the group name itself comes from its well-known SID via `LookupAccountSid` so localized Windows works.
   After the change the same capture finished in **2.08 seconds**.

## What it deliberately does not record

Only `enabled|disabled` and `administrator|standard user` go into the baselined value. A last-logon timestamp would
make every sign-in look like a modification, and the product does not collect user activity. Account names are stored
locally because the feature is worthless without them; they never leave the machine.

## Verification

- Debug build: 0 warnings, 0 errors. **1,563 tests pass** (6 new in `LocalAccountPersistenceTests`).
- The harness confirmed 8 accounts and 2 administrators on the building machine, then was removed.
- **Not viewed:** the Persistence page with the new category selected.

## Package

Placeholder — filled after packaging.
