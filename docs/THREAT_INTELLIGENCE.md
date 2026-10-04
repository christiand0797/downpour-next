# Threat intelligence ingestion

## Current source

The Threat Intelligence route currently downloads the CISA Known Exploited Vulnerabilities (KEV) catalog from the fixed endpoint `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. CISA describes KEV as a source for vulnerability-management prioritization: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

The route is advisory and read-only. It does not match installed products, claim that this machine is vulnerable, start scans, or change system state. It labels the source and catalog release/retrieval times, supports local search, and reports fetch/validation failures without substituting fake or stale data.

## Ingestion controls

- HTTPS to a hard-coded CISA host; automatic redirects are disabled and the final response URI is checked.
- A 15-second request deadline and a 12 MiB streaming payload limit, checked even when the server omits `Content-Length`.
- JSON depth capped at 24, no comments/trailing commas, at most 10,000 records, bounded field lengths, and strict required fields/date/CVE validation.
- Duplicate CVE identifiers are rejected. Response bodies are treated only as data and are never executed or used as paths/commands.
- UI rendering is capped at 500 rows per filtered result. The full validated catalog can be searched locally in memory.

## Limitations and next steps

This prototype does not persist a catalog cache, verify a detached signature (the selected feed does not currently provide one through this integration), correlate KEV entries with installed software, ingest EPSS/NVD/URLhaus/MISP/TAXII, or evaluate Sigma/YARA rules. The current freshness label reflects a successful retrieval in the current app session. Add authenticated/versioned local cache metadata and explicit age limits before offline reuse; add each additional feed as a separately allow-listed parser with its own provenance and failure state. Document Sigma and YARA compatibility before porting those rule formats.

The endpoint is chosen from the official CISA catalog. CISA's web page was not directly fetchable in the research browser during implementation (HTTP 403), so the client also rejects redirects and shows a clear unavailable state if the JSON endpoint is blocked or changes.
