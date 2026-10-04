# Operation journal foundation

The sensor service initializes a versioned SQLite journal at `%LOCALAPPDATA%\DownpourNext\state\operations.v1.db`. Its containing `state` directory has an explicit protected Windows DACL granting full control only to the current service account and LocalSystem. Existing database/WAL/SHM files are checked for reparse points; existing files have their explicit ACL reset to the same principals before opening. New SQLite files and sidecars inherit the protected directory ACL.

Schema version 1 contains:

- `operations`: current operation projection, fixed operation kinds (`QuarantineFile`, `RestoreFile`), fixed state vocabulary, actor SID captured from the service process, bounded policy version, opaque object ID, and UTC timestamps.
- `operation_events`: append-only-by-API transition history with a unique event ID, monotonic SQLite sequence, previous/current state, bounded reason code, and UTC timestamp. SQLite triggers reject updates and deletes to event rows.
- `schema_migrations`: applied schema versions.

Every transition updates the operation projection and appends its event in one SQLite transaction. SQLite uses WAL, foreign keys, a five-second busy timeout, and `synchronous=FULL`. The API enforces state transitions, idempotent event replay, opaque path-free object identifiers, ASCII reason-code bounds, and bounded pending/event query sizes. A restart leaves unfinished intent visible as pending recovery; nothing automatically resumes or changes files.

## Deliberate scope boundary

This journal records intent and state only. It does not expose IPC, authorize consent, execute commands, move files, or enable quarantine/restore. It is not a complete audit subsystem: it currently has no retention/rotation policy, UI/history view, signed checkpoint, DPAPI key, or independent server identity verification. SQLite triggers prevent accidental API mutation, not a database owner from changing the database directly.

Portable mode runs the service as the signed-in user. The ACL blocks other local user accounts, but malware running under that same user or an administrator can alter the journal and any future same-user quarantine storage. Therefore the journal is not tamper-proof or nonrepudiable. A future action broker must choose and install a deliberate service identity, authenticate the requesting desktop user, record consent/policy as a verified typed request, and fail closed if audit persistence fails. No action IPC should be added to the current read-only pipe.

Next work: add bounded retention and audit verification, then define the typed action broker and crash-reconciliation protocol. Only after those pieces are reviewed and tested should a separate slice implement encrypted, hash-verified quarantine and non-overwriting restore.
