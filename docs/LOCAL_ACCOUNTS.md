# Local accounts in the persistence sweep

## What it adds

The persistence inventory now lists every local Windows account and whether it is in the built-in Administrators
group, alongside Run keys, scheduled tasks, WMI subscriptions and drivers. Each account is an entry in the same
trust-on-first-use baseline as everything else, so:

- the first sweep records the accounts that exist and calls nothing new;
- an account created afterwards is **new**, and the finding says whether it is enabled and whether it is an
  administrator: `CRITICAL` for a new enabled administrator, `HIGH` for a new enabled standard user, `MEDIUM` for a
  disabled one;
- an existing account added to Administrators is a **modified** entry and raises the same `CRITICAL` finding, which is
  the local half of T1136.001;
- an account that disappears is a removal in the change digest.

The entries are read-only facts. Nothing here enables, disables, deletes or changes an account, and no policy is
turned on.

## Why the implementation looks the way it does

- **Unelevated.** `NetUserEnum` and `NetUserGetLocalGroups` are ordinary queries; no administrator token is needed.
- **One `NetUserEnum` call.** `MAX_PREFERRED_LENGTH` returns every account in a single buffer. The first version
  paged with a resume handle and silently appended duplicates until it hit its 256-entry cap — the probe caught it
  reporting 256 accounts on a machine with eight.
- **Membership per account, not by enumerating the group.** `NetLocalGroupGetMembers` at level 3 resolves every
  member's account name, including domain principals. On a machine whose domain controller is unreachable that call
  blocked for minutes inside the service's capture path — the probe hung on the first run. `NetUserGetLocalGroups`
  resolves only local group names, so it cannot stall on the network. The Administrators group name itself comes from
  its well-known SID via `LookupAccountSid`, which is local and therefore correct on a localized Windows install.
- **No logon times.** The baselined value is only `enabled|disabled` and `administrator|standard user`. A last-logon
  timestamp would make every sign-in look like a modification and would record activity the product deliberately does
  not collect.

## Verification

- Debug build 0 warnings / 0 errors; **1,563 tests pass** (6 new in `LocalAccountPersistenceTests`).
- A harness run on the building machine captured 8 accounts and 2 administrators in 2.08 seconds, with values of the
  expected shape. The harness was temporary and is not committed.
- Not viewed: the Persistence page with the new category selected. The category is in the filter list, but the screen
  itself was not looked at.
