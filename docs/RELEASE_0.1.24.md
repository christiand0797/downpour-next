# Downpour Next 0.1.24

0.1.24 makes the threat catalog honest about which sources still work, adds six live community lists, and lands
tested groundwork for release signing, investigation views and quieter triage. No new mutating action is enabled;
the product remains read-only apart from the previously reviewed confirmed fixes.

## Threat sources

- Every catalogued endpoint was exercised end to end on 2026-11-19 (download plus strict parse), not just assumed to work.
- Six **TweetFeed** CC0 lists are now downloaded: malicious domains, corroborated domains, IPs, corroborated IPs, full URLs (hosts are indexed) and SHA-256 hashes. The active catalog is **58 sources**.
- `threatfox`, `urlhaus` and `malwarebazaar` now answer **HTTP 410** without a free abuse.ch `Auth-Key`, and PhishTank redirects to an expiring signed CDN URL. Those four are **retired**: they remain catalogued so historical alerts keep their source name, but they are never downloaded, cached or listed. Feodo Tracker and Phishing Army still cover those categories.
- The unpublished candidate's four Emerging Threats blocklist URLs returned 404 and were dropped; Feodo, CINS, Tor and DShield already cover them.
- A malformed URL can no longer escape the parser as `IndexOutOfRangeException`; the fuzzer that found it now passes. URL-column CSV parsing also handles quoted fields containing commas, so a URL cannot shift the host column.

## Foundations (tested, not yet exposed in the UI)

These are building blocks with unit coverage; none of them changes a route's data path yet.

- Release manifest signature verification with a pinned public key, and installed-file integrity checking against a hashed manifest.
- A feed-update plausibility guard: a list that collapses below a quarter or grows fourfold keeps the last accepted copy instead of silently degrading matching.
- A ranked local change digest, an evidence graph for investigation paths, a per-machine behaviour baseline, encrypted-DNS endpoint recognition and alert grouping.
- A validated portable threat-pack format for offline import/export, and retention policy for local evidence.
- Rule-quality budgets loaded from the scanner's clean-corpus measurements, a 200,000-domain index performance gate, and a self-hosted release-gate workflow for when hosted Actions minutes are unavailable.
- Authenticated feed downloads (`Auth-Key`) with the header supplied from settings; the Settings entry and the three abuse.ch feeds stay disabled until that key can be stored.

## Verification

Release build and the full test suite ran from the tagged source; the packaged archive, CycloneDX SBOM and SHA-256
manifest are attached. Native window and route smoke results are recorded with the release. Binaries remain unsigned;
see `docs/RELEASE_TRUST.md` for the signing plan and what is still missing.
