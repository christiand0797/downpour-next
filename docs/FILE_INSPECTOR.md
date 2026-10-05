# File Inspector

The Scanner navigation route currently offers a user-selected static PE metadata inspection. Select one local `.exe`, `.dll`, or `.sys` file (maximum 256 MiB). Downpour reads the file as bytes, calculates SHA-256, and parses bounded PE headers for architecture, section count, PE timestamp, writable-plus-executable section count, and embedded certificate-table presence.

## Safety and limits

- The selected file is never executed, uploaded, modified, quarantined, or persisted by this feature. Only the file name and inspection output are displayed in memory.
- Parsing is read-only, rejects malformed/out-of-bounds PE offsets and more than 96 sections, and never allocates the entire file. Hashing streams from the selected file.
- An embedded certificate table is only reported as present/absent. Signature integrity, certificate chain trust, signer identity, revocation, and reputation are not checked.
- Writable-plus-executable section counts are structural review indicators, not proof of malicious behavior. Packed/protected legitimate software can have unusual PE metadata.
- A SHA-256 value identifies the bytes; it does not make a reputation or safety claim. There is no malware detection engine, YARA support, recursive scan, process scan, or remediation in this slice.

Parser tests cover valid PE metadata, non-PE hashing, malformed offsets/certificate ranges, and early rejection of oversized input. Native file-picker click-through remains a manual Windows UI check.
