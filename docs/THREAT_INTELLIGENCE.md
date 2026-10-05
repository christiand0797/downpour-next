# Threat intelligence ingestion

## Current source

The Threat Intelligence route currently downloads the CISA Known Exploited Vulnerabilities (KEV) catalog from the fixed endpoint `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. CISA describes KEV as a source for vulnerability-management prioritization: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

The route is advisory and read-only. It labels the source and catalog release/retrieval times, supports local search, and reports fetch/validation failures. A previously validated cache can be shown during a network failure with an explicit age/state label.

## On-demand EPSS enrichment

After selecting a CVE row from the validated CISA catalog, the user can explicitly request its current score from FIRST's [EPSS API](https://api.first.org/epss/). The request sends only that CVE identifier to the fixed HTTPS host `api.first.org`; Downpour does not upload the catalog or perform bulk lookups. The lookup is bounded by a 10-second deadline and a 64 KiB response limit, rejects redirects, validates the final host/path, applies strict duplicate-property JSON parsing, requires an exact CVE match, constrains score and percentile to 0–1, and checks the score date. A recent result for the same selection is held in memory for up to 24 hours; no EPSS response is written to disk.

FIRST defines EPSS as a population-level estimate of the probability that a published CVE will be exploited in the wild over the next 30 days; the score is not an asset-specific risk or proof that an installed product is vulnerable ([FIRST EPSS overview](https://www.first.org/epss/), [data access guidance](https://www.first.org/epss/data.html)). The page displays the score date, retrieval time, probability, and percentile with that limitation. NVD CVSS/CPE analysis is not implemented.

## Local installed-software candidate review

The Vulnerabilities route asks the local sensor service to enumerate Windows uninstall registry keys from the machine and current-user hives in 32-bit and 64-bit views where available. It reads only `DisplayName`, `DisplayVersion`, `Publisher`, and the `SystemComponent` filter flag. It does not read install locations, uninstall commands, product codes, or registry values used to launch software. Collection is bounded to 20,000 subkeys inspected, 1,000 display rows, 160 characters per field, and 16 warnings. Results stay on the device and travel over a current-user-restricted, output-only named pipe with a five-second client timeout and schema/field validation.

An explicit local comparison checks normalized publisher/application names against CISA KEV vendor/product text. It excludes generic product labels, requires vendor evidence and the product phrase at the end of the application display name, and caps output to 250 candidates. This conservative rule intentionally misses products with suffixes or alternate branding. Conversely, names are not authoritative product identity: a candidate does not establish affected version, edition, component, installation state, exploitability, or patch status. Treat each row as a lead to verify with the vendor/CISA advisory. No vulnerability verdict, remediation, uninstall, or state change is performed. Applications not registered in the Windows uninstall registry are absent.

## Ingestion controls

- HTTPS to a hard-coded CISA host; automatic redirects are disabled and the final response URI is checked.
- A 15-second request deadline and a 12 MiB streaming payload limit, checked even when the server omits `Content-Length`.
- JSON depth capped at 24, no comments/trailing commas, at most 10,000 records, bounded field lengths, and strict required fields/date/CVE validation.
- Duplicate CVE identifiers are rejected. Response bodies are treated only as data and are never executed or used as paths/commands.
- UI rendering is capped at 500 rows per filtered result. The full validated catalog can be searched locally in memory.
- The raw catalog is saved under `%LOCALAPPDATA%\DownpourNext\threat-intel\cisa-kev.v1.cache` with a versioned fixed-size header, retrieval time, strict payload length, and SHA-256 corruption check. Writes use a unique temporary file, flush, and atomic replacement; only data that passes the same parser is stored.
- Cache reads repeat the size, digest, UTF-8, JSON, envelope, duplicate-CVE, and field checks. Data older than seven days or dated more than five minutes in the future is not used. Entries older than 24 hours are explicitly labeled stale. A cache digest detects accidental corruption; because it is stored beside the cache, it is not an authenticity signature against an attacker who can rewrite the entire user cache.
- If a refresh fails, the page keeps a validated in-memory/cache catalog visible and says the source is unavailable; it does not present the cached data as current.

## Limitations and next steps

This prototype does not verify a detached signature (the selected feed does not currently provide one through this integration), perform affected-version matching, ingest NVD/URLhaus/MISP/TAXII, or evaluate Sigma/YARA rules. EPSS currently enriches one user-selected KEV CVE at a time; bulk EPSS ingestion is not implemented. Add each additional feed as a separately allow-listed parser with its own provenance and failure state. Document Sigma and YARA compatibility before porting those rule formats.

The endpoint is chosen from the official CISA catalog. CISA's web page was not directly fetchable in the research browser during implementation (HTTP 403), so the client also rejects redirects and shows a clear unavailable state if the JSON endpoint is blocked or changes.
