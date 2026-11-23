# Downpour Next 0.1.42

A connection used to be described only by its country and the name of the network that announces it. That leaves the
most interesting case silent: an address on no indicator list that belongs to a network which exists to host crime.
0.1.42 adds the first catalogued source keyed by **network owner**, and carries its answer on every connection.

## Network reputation, not just a country

- **Spamhaus ASN-DROP** (`asndrop.json`, Spamhaus DROP terms) names autonomous systems Spamhaus says should not be
  routed: bulletproof hosting and criminal infrastructure. It is downloaded whole over HTTPS, parsed by its own strict
  NDJSON parser, cached under `%LOCALAPPDATA%\DownpourNext\threat-db`, and matched entirely offline.
- The listing is attached to **every established TCP connection**, not only to rows that already matched an indicator,
  so a clean address on a listed network is visible for what it is. The Network page appends `ASN-DROP: <name>` to the
  network column and marks the row, the detail pane names the listing, and the case file records it.
- The wording is deliberately exact: *"Spamhaus ASN-DROP names this network: … That is a property of the network's
  routing, not evidence about the program using it."* A listed network with no database match still grades **likely
  benign** — only the reason text changes. A test pins that rule.
- A snapshot warning counts how many connections reach listed networks, worded the same way.

## Sources

- **Added:** Spamhaus ASN-DROP (network ownership), OffSeq Mirage 7-day honeypot attackers (CC BY 4.0, TLP:CLEAR).
- **Retired:** Threatview's MD5 feed answered HTTP 200 with **0 bytes** on 2026-11-23. An empty response cannot be told
  apart from a truncation, so the strict parser already refused it; the entry is retired with that reason instead of
  showing a permanent failure. The provider's SHA-1/SHA-256 feed, Mandiant and DigitalSide still supply hash evidence.
- **Active catalog: 59 sources.**
- **Examined and left out, with reasons** in [`RESEARCH_2026-11-23.md`](RESEARCH_2026-11-23.md): SANS ISC
  `threatintel.txt` and `domaindata.json.gz` (CC BY-NC-SA terms unresolved), ThreatHive (no stated licence), `ip-db.com`
  (documented path returned 404), AlienVault `reputation.generic` (undated, unlicensed), Bambenek (HTTP 403). No Tor,
  paste site or criminal market was accessed, and the document says why that is a design rule rather than a limitation.

## Why this matters more than another blocklist

The research also records the gaps that would beat any additional list: newly observed domains (the strongest phishing
and loader signal, blocked on the SANS licence), sequencing the Sysmon events already collected into behaviour chains
rather than counting ATT&CK tags, and egress byte volume. Those are the next real improvements, not a bigger source count.

## Verification

- Debug build: 0 warnings, 0 errors. **1,552 tests pass** (5 new in `AsnReputationTests`).
- Release build: 0 warnings, 0 errors, **1,552 tests pass**.
- **All 58 downloadable feeds parsed from their real endpoints** on this machine (`DOWNPOUR_LIVE_FEEDS=1`), including
  both new sources. This is what found the empty Threatview MD5 feed.
- Packaged route smoke (every route, 179 YARA rules) and window smoke passed.
- One first Release run failed `AlertSnapshotAndTriagePipesExchangeBoundedLocalData` at its 10-second pipe-startup
  window under full-suite load; the same test passed isolated in 252 ms and the full Release suite then passed. Both
  results are recorded rather than the failure being dropped.

## Package

- `DownpourNext-win-x64-0.1.42.zip` — 306,622,248 bytes, SHA-256 `9988f2979e66ce896cdad12f9561e2b6d91114f492797ce7781c5270cefc1bdf`.
- `DownpourNext-0.1.42-sbom.cdx.json` — 26,237 bytes, SHA-256 `3b182325ccb8bc7a68214895015a9013d662036872d78e4cf5a7673b0863054e` (52 components).
- `DownpourNext-0.1.42-SHA256SUMS.txt` — 198 bytes, SHA-256 `766365600287effa4aa799a17c88cfaa8a5d4f499220b8dd86564176c4574971`.
- 1,077 entries, 772,932,818 expanded bytes, 52 runtime components. Every executable reports
  `0.1.42+d47f060256069fdbc4d9e2da915501096d758207`.
- Placeholder-free copy of these notes: published as the release body.

## Limits

- The Network column marker, detail row and warning were **not viewed** on screen; the strings and behaviour are pinned
  by tests only.
- A network listing is context. It does not establish that a program is malicious, that a person is involved, or that a
  connection was unwanted.
- No privileged action, no blocking, no new data leaves the PC.
