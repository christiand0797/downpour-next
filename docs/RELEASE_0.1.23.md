# Downpour Next 0.1.23

This release expands locally searchable threat coverage and makes source age visible in Downpour.

- HaGeZi Threat Intelligence uses the full maintained domain feed instead of the mini subset. The verified snapshot yielded 2,101,965 usable domains. The source count remains 55; overlapping feeds are not counted as independent proof.
- The exact indicator index uses compact sorted storage, preserves source attribution and verifies full strings. In a separate-process full-feed comparison, additional managed index storage fell from 148.1 MB to 33.6 MB, with somewhat slower lookups. These are local single-feed measurements; it remains an in-memory index.
- Threat Databases and Threat Intel Feeds distinguish source publication from download time. Expired network snapshots and historical network archives are excluded from current matching while remaining browsable. Historical file fingerprints retain their distinct meaning.
- Local feed search covers the whole dataset and has Previous/Next navigation. Only the current page's rows are allocated for display; queries stay on the PC. Search cancellation and changing selections do not let an old response overwrite a newer search.
- Malformed URL host input cannot crash manual lookups. An updated cache generation keeps the old HaGeZi mini cache from being labeled full.
- The existing Windows Update installer now requires complete successful searches before downloading or installing. Failed, aborted, partial and warning-bearing searches cannot silently become an all-clear or a partial installation batch. Interactive-only offers are distinguished from no available updates.

- NVD affected-version analysis now uses NVD's real range fields (`versionStartIncluding`/`versionStartExcluding`, `versionEndIncluding`/`versionEndExcluding`). A concrete CPE version is exact rather than a minimum, pre-release suffixes sort below the release, and unknown installed versions remain conservative. This removes false "affected" rows for later patch builds; a row is still a lead, not proof that the installed build is vulnerable.
- Indicators never leave the PC for reserved or special-purpose address space, now including Teredo, ORCHID, IPv6 benchmarking/documentation blocks and the IPv4 6to4 relay anycast range.
- DGA scoring no longer flags non-routable suffixes, reverse-lookup zones, DNS service labels or punycode names, and dictionary-word discounts require a whole label instead of a substring.
- Three ordered cross-source correlations were added: account creation followed by a local group change (15 minutes), Defender malware detection followed by a service installation (30 minutes), and a failed-logon burst followed by a Remote Desktop authentication (15 minutes). Each states that timing alone does not establish a shared actor.

## Verification

Debug restore/build completed with zero warnings/errors; all 1,397 tests passed (21 new for NVD ranges, indicator filtering, DGA precision and correlation ordering). Supported metadata formats, in-memory expiry, historical hash behavior, complete provenance, stale-scan publication, local pagination, query cancellation and update-search failures have regressions. Full-feed parsing and separate-process index measurements passed. The clean committed Release build, packaged archive digests and native results accompany the uploaded assets; publication uses the exact tagged source commit.

## Remaining work

This does not claim complete v29 parity or universal driver availability. The portable application remains unsigned, same-user trust limitations remain, and clean-machine/privileged crash-recovery acceptance is still open. Persisted central alerts from earlier service runs are historical observations and may outlive their source evidence; durable source attribution for that history remains unfinished. Targeted driver installation, cancellable WUA search, protected-log access through an in-app broker and native SMB1 servicing remain queued direct-operation work. No privileged changes were performed during this verification.
