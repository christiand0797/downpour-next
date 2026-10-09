# Downpour Next changelog

## Unreleased

- **Downpour now fixes things itself.** A new administrator helper (Downpour.Fixer) applies hardening fixes, Defender settings, attack surface reduction rules and firewall changes, and downloads and installs Windows security updates and Microsoft-signed driver updates, after a single Windows permission prompt. Hardening has a **Fix** button on every fixable finding and **Fix all recommended** (fixes without side effects); fixes with side effects explain them first. Every changed setting is backed up, a fix that fails part-way is rolled back, every run is written to a tamper-evident log in an administrator-only folder, and **Undo last fixes** restores everything. **Install updates now** on the CVE Dashboard and Hardening, and **Install driver updates** / **Find and install driver** on Devices & Drivers, replace the links to Windows Settings and vendor download pages. Downpour never restarts the PC itself and never runs vendor installers downloaded from websites.

- **Settings → Storage & cache**: shows how much space Downpour's caches use (leftover temporary files, downloaded app updates, logs, the vulnerability catalog, the 45 threat databases, emergency snapshots, learned baselines) and cleans the ones you select after confirmation. Files in use are skipped; the tamper-evident action log, quarantine, alert history and settings are never removed, and links or junctions are never followed.

- **CVE Dashboard** tab (v29 parity): the CISA Known Exploited Vulnerabilities catalog related to this PC. Windows flaws added after your newest update are flagged as likely missing (on the owner's PC: 16, because no update has installed since 2025-10-25), installed apps are matched by name, and ransomware-used flaws are counted. Charts for new exploited flaws per month, the most exploited vendors and how the catalog relates to this PC; filters by scope (likely missing, installed apps, Windows, Microsoft, ransomware) and year; each CVE opens CISA's required action and deadline, ransomware use, notes, an on-demand EPSS exploit probability, and the NVD and Microsoft advisories.

- **Hardening grows from 9 to 43 checks** with a hardening score: everything v29's system hardening and firmware checks covered (Defender cloud protection, sample submission, potentially unwanted apps, tamper protection, definition age, firewall on every network type, UAC, Remote Desktop, AutoRun, PowerShell policy, Guest account) plus NSA and CIS recommendations: ransomware folder protection, network protection, attack surface reduction rules, SmartScreen, the vulnerable driver blocklist, Remote Assistance, built-in Administrator, auto sign-in with a stored password, PowerShell 2.0 and script logging, LLMNR, NetBIOS, WDigest clear-text passwords, LM hashes, NTLMv1, anonymous account listing, SMB signing, SMBv1 client, PrintNightmare (CVE-2021-34527) Point and Print, Remote Registry, WinRM, how long ago updates were installed, and whether this Windows version still gets security updates. Each finding says exactly how to fix it, with an **Open setting** button for the right Windows Security or Settings page, a **Copy fix list** button, a filter, and a findings-by-area chart. Downpour still never changes these settings itself.

- **26 more threat databases (45 in total)**, all public, keyless and matched locally: attack-framework command servers (C2IntelFeeds, Threatview Cobalt Strike), APT and malware indicators and file hashes (Signature-Base), the hacking tools stolen from FireEye, NSO Pegasus and Cytrox Predator spyware servers, HaGeZi threat intelligence, CERT Polska, ransomware, scam, cryptojacking and malware domain lists, more attacker reputation lists (Emerging Threats, FireHOL, DShield, BruteForceBlocker, IPsum 5+), and **LOLRMM**: 358 remote-access tools (AnyDesk, TeamViewer, ScreenConnect, RATs) so remote-control software running on the PC or reaching its servers is shown. Verdicts weight each list by what it means: spyware lists like stalkerware, C2 and malware lists above reputation lists.
- **Security log access explained and fixable**: instead of "Permission denied reading Security" plus a misleading live read error, Security Events says Windows only lets administrators and the Event Log Readers group read the Security (and Sysmon) log, and an **Enable protected logs** button shows the least-privilege fix: a copyable command that adds your account to Event Log Readers (works in every Windows language), or the Computer Management steps. Downpour keeps running with normal rights and never changes group membership itself. Unreadable logs are no longer subscribed to, and a live read error is reported once instead of on every event.
- **Drivers tab verifies and judges every loaded driver**: each driver's signature is checked on this PC (embedded Authenticode, then the Windows catalog) and shown with its signer, and each gets a verdict: known malicious (its exact hash is in LOLDrivers), legitimate but vulnerable (BYOVD), loaded from a user-writable folder, not validly signed, Windows driver, or signed vendor driver. Problems sort to the top; a signatures chart joins the location, folder and count charts; click a driver for the reason, its hash and a threat-database lookup.
- Click any row on Processes, Drivers, Driver Packages, Services, Network, Security Events, DNS, Persistence, Devices & Drivers, Alerts (and correlated incidents), Triage, Threat Databases (matches and connections), Threat Intel Feeds, Vulnerabilities (software and KEV matches), USB (findings, drives, history), Wi-Fi & Bluetooth, Forensics and the Investigation timeline for full details (Memory, IoT and Emergency keep their detail panes and add the right-click menu) (file hash, signature, threat-database and IP-origin lookups); right-click for actions such as open file location, file properties, YARA scan, end process, quarantine or block an address, each previewed and confirmed.

## v0.1.19 — Devices & Drivers, rootkit check, per-tab charts, reliability

- **Fixed for other PCs**: Threat Databases and Threat Intel Feeds no longer report "the sensor service did not answer" on networks or PCs where a download or saved copy fails (owner laptop report); one failing sensor no longer stops the rest; the service keeps a troubleshooting log.
- **Fixed**: alert lists, threat counts and Threat Pulse went blank once a graded service-install alert existed (never released; caught before this release).
- **Host isolation recovery** keeps its scheduled release and reports failure when firewall cleanup or rollback is incomplete; recovery intent is saved first and failed scheduled cleanup retries.
- Portable builds include the HUD backdrop, crescent moon and tray icon again.
- **Devices & Drivers** tab: every device with its status and Device Manager problem code explained in plain words with a fix, devices missing a driver, oldest drivers, driver signers, and a read-only Windows Update search for driver updates with the device each one is for. Install, roll back, uninstall and reinstall open in Windows' own Optional updates and Device Manager (they ask for administrator rights themselves). The Drivers tab links to it. Because many drivers never reach Windows Update, it also reads each device's chip maker from its hardware ID, recognises your PC or motherboard maker and the official updater apps you have installed, and lists graphics, network, audio, chipset and storage drivers worth checking with the maker, each with a button to the maker's verified official page (Downpour never downloads or runs installers).
- Charts on Processes, Drivers, Driver Packages, Network, Security Events and Services, each built from that tab's own data.
- **Rootkit check**: every ten minutes Downpour probes every process ID directly and compares the answers with Windows' process list; a running program hidden from the list raises a critical alert. Exited and just-started programs are excluded so normal activity cannot trigger it.
- **Kuro plays**: fireflies drift around him; he watches them, pounces, lies down for a while and rolls along his card, and faces you instead of turning away.
- **Anti-Stalker 24-hour timeline**: one row per camera, microphone, screen capture, location and remote control showing exactly when each was in use.
- Threat databases and intel feeds work on slower or filtered networks and explain why an update failed; one failing sensor no longer stops the others; the service keeps a log for troubleshooting.
- **Threat Pulse** on the Dashboard: Downpour learns how many new findings per hour are normal for your PC and shows the last 24 hours as a pulse, flagging a spike when something unusual starts.
- **Tamper-evident action log**: every quarantine, process end, firewall, USB and host-isolation action is now chained with a keyed hash, so editing, deleting, reordering or cutting off records is detected. Downpour checks the chain at start and every ten minutes and raises a critical alert if it was altered; the case file shows the result.
- Service-install alerts now say which service was installed, which program it runs and who signed it, and are graded by that: Microsoft-signed components are low, signed apps (for example Claude, ChatGPT or NVIDIA services) medium, unsigned ones high, and services that run a command shell (how remote-control attack tools work) critical. The program file is attached as evidence.
- The case file shows the evidence behind each alert (scanned file, service program) and includes an Audio Shield section.

## v0.1.18 — threat databases, HUD theme, live updates

- **Threat Databases**: 19 public databases (LOLDrivers, LOLBAS, abuse.ch ThreatFox/Feodo/URLhaus/MalwareBazaar, Spamhaus DROP, Emerging Threats, FireHOL, IPsum, CINS, GreenSnow, blocklist.de, Tor exits, Phishing Army, OpenPhish, stalkerware indicators, IPtoASN) downloaded whole, validated, cached and matched on this PC against connections (with owning program), the DNS cache, loaded drivers and running programs. Offline lookups, connection origins (country and network) and a copyable evidence report.
- **Threat Intel Feeds** browses the local databases; the old abuse.ch API calls needed a registered key and failed.
- **CISA KEV** loads again (CISA switched dateReleased to a timestamp).
- **Audio Shield** tab: shows which programs are listening to your microphone (or recording everything you hear) with live levels, every audio device including new, Bluetooth, virtual and Stereo Mix inputs, the effect DLLs loaded into the Windows audio engine with signature checks, and what is causing crackles, dropouts or silence. Each problem has its fix: end the program or quarantine the file (previewed, confirmed, audited, restorable) or open the exact Windows setting.
- Fewer false alarms from startup items and drivers: signed vendor autostarts such as Microsoft Edge's cleanup task are now low priority, and signed vendor drivers with known flaws are reported as "legitimate but vulnerable" instead of critical.
- Fixed rare crashes in the cherry-blossom scene and when closing the app.
- **Anti-Stalker** tab; **host isolation** completed with an OS-scheduled release; **Parental Controls** crash fixed.
- **Drivers** list works on Windows 11 24H2+ (kernel addresses are hidden from standard accounts).
- **HUD theme** across the app: neon controls, Bahnschrift type, HUD ring gauges and glowing charts over the rain.
- Settings switches for host isolation and threat database updates.
- **Live every second**: every monitoring page updates each second without flicker; slow scans run in the background and never block the view.
- **Verification engine**: every database match is double-checked against independent evidence (how many databases agree, whether a program actually connected, digital signatures, browser vs unknown program) and shows a verdict, confidence and reasons. Names already blocked by your hosts file or DNS filter are recognised and cleared; built-in Windows firewall rules and optional hardening tips no longer appear as threats.
- **Export case file**: one click saves every finding with its evidence and instructions so a reviewer or AI agent of your choice can double-check before you act.
- **Sakura Sentinel**: a cherry tree floats over the Dashboard and Performance pages; its petals drift down and land on the cards themselves, faster as your PC gets busier. Kuro the cat sits on a card with his tail draped over the edge, sweeping petals aside, swivelling his ears, tilting his head, blinking slowly at you, and staying on guard while threats are open.
- Glowing gradient meter bars everywhere; the Performance page fills its width with live history charts.
- Per-disk I/O now shows every physical disk; maximized window content stays above the taskbar.
- Repeated low-severity PowerShell/process/privilege events roll up into one alert per hour with an accurate count; the dashboard status strip reflects the real engine and action state.

## v0.1.17 — measured CIS review and package integrity

- Replaced scripted CIS detector counts, resistance/confidence scores, forecasts, pretend honeypots and swarm protection controls with real validated alert/system/settings measurements. Removed unused simulation code/contracts and replaced their model tests with behavioral regressions.
- Displays returned-window scope, open/urgent/user-verified/suppressed counts, techniques, actual source warnings and cautious temporal correlations; unavailable data stays unknown. Refresh/cancellation follows page lifetime, and an explicit local metadata report includes limitations.
- Added a bounded explicit package-file consistency check with strict schema/version/path/size/hash validation, missing/mismatch/unreadable outcomes, cancellation and a 30-second deadline. The unsigned local manifest remains replaceable and is not publisher authentication or malware clearance. See CIS.md.
- Debug build clean; 893 working-tree tests passed. Clean committed Release build: 0 warnings/errors; 870 tests passed, 0 skipped. The 28 new measured/integrity cases cover real bytes, tampering, bounds, malformed paths/contracts, cancellation and actual link rejection on this host.
- Packaged desktop/service/scanner lifecycle smoke passed with 179 YARA rules and a benign scan. Actual new integrity workflow matched all 1,061 manifest-listed files (659,846,854 bytes hashed); a live review/report probe returned measured alerts and partial-source warnings. Native CIS click-through remains outstanding.
- Source: `e8ce959cc0c8238e3eed0b86e9a5894d36874485`. Archive: `DownpourNext-win-x64-0.1.17.zip`, 259,783,061 bytes; SHA-256 `B035C921C7F9A1BF1DB7222448EEECD6C3C5E43932A6F60B9BC8C77FA843DBB2`. All 1,062 archive entries hash-match staging; SBOM lists 52 runtime components.
- Full adaptive/deception CIS, admin elevation, host isolation, driver lifecycle execution, broader v29 parity, installer/signing and complete native acceptance remain unfinished. Pre-existing host-isolation/AntiStalker drafts are preserved and excluded.

## v0.1.16 — detection reliability and connected migration slices

- Sysmon review events 8/9/25 now reach persisted alerts through validated catalog entries. Normal telemetry remains telemetry; labels are corrected, clipboard activity is excluded, real polling supplements subscriptions, and unavailable channels/queue/persistence failures are visible.
- AMSI errors are unavailable rather than clean; the full malware result range is recognized. Native context lifetime, retry, dedup bounds, event identity and shared detection-health warnings have regression coverage.
- Settings exposes real process, firewall and USB broker-policy switches alongside quarantine. Each action still requires a separate preview/confirmation and Windows permissions. Privacy/action text now describes the actual local data and action paths.
- Includes the committed migration slices since v0.1.14: selected-file YARA-X scanning and bundled rules, consented PowerShell analysis, local posture/investigation routes, and consent/audit brokers for quarantine/restore, process termination, expiring IP firewall rules and reversible USB controls. These are functional slices, not complete v29 parity.
- Centralized compiled version metadata at 0.1.16 and fixed portable WinUI theme-resource generation by setting deployment mode before build. Final desktop/service/scanner smoke passed; 179 YARA rules loaded and a benign fixture scanned without matches.
- Clean Release build: 0 warnings/errors; 856 tests passed. Final text-only XAML publish succeeded; working-tree Debug tests: 879 passed, including 23 uncommitted draft tests excluded from the release. All 1,062 archive entries match their staging hashes.
- Source: `ffc241d2806ccdf616c738c2ad5453d962eb4280`. Archive: `DownpourNext-win-x64-0.1.16.zip`, 259,810,553 bytes, SHA-256 `36503A9AEB68F67E763F13F4DACFC76C7161163F04A1C146FB071CBF085059EA`. Includes runtime SBOM and file manifest. Binaries remain unsigned.
- Host isolation/AntiStalker drafts are excluded. Automatic admin elevation, full operational AEGIS/CIS, driver execution, installer/signing and complete native acceptance remain unfinished; see CONTINUATION_AUDIT.md. v0.1.15 was a local package milestone and was never published on GitHub.

## v0.1.15 — Disk telemetry and stable refresh updates

- Added locale-independent Windows PhysicalDisk total read/write byte-rate counters, with unknown values during warm-up and when counters are unavailable.
- Added dedicated physical-disk read/write gauges, two-minute history, bounded CSV columns, and snapshot validation for nonnegative disk rates.
- Updated live process, network adapter, TCP connection, and Performance lists in place by stable ID to prevent full-list flashing during refresh. Unchanged gauge values no longer regenerate their ring geometry.
- Dashboard retains the last chart while the sensor is offline and labels its availability state.
- Release build and all 118 tests are pending in the isolated pushed-source tree; portable package and release metadata will be recorded after verification.

## v0.1.14 — Performance telemetry and gauges

- Expanded Monitoring > Performance with six live gauges: CPU, physical memory, system commit, OS-volume usage, combined active-adapter receive, and send. Added commit history and committed/limit fields to bounded CSV export.
- Added service-side per-process CPU percentages from cumulative CPU-time deltas. Values normalize to total logical-processor capacity, remain unknown on first/inaccessible samples, and reset on process start-time changes to avoid PID-reuse carryover.
- System-wide commit uses Windows `GetPerformanceInfo`; page counts convert to bytes with the reported page size. The UI does not treat process-limited paging-file counters as system-wide.
- Fixed dashboard, network, and Performance chart crashes caused by sharing a WinUI `PointCollection`; clarified graph units, time direction, missing-data gaps, and current-sample markers. System-volume metadata now reads off the UI dispatcher.
- Corrected the updater's embedded current version to 0.1.14 so the new package no longer reports itself as an older install.
- Release build: 0 warnings/errors; 117 tests passed. Portable build is self-contained and unsigned; this does not complete v29 parity. Per-core CPU, physical disk I/O, pagefile storage usage, GPU/thermal/power readings, and native Performance/save-picker click-through remain open.
- Package: `DownpourNext-win-x64-0.1.14.zip` (196,796,799 bytes); SHA-256 `B5C723A9DC15FEDA679BA735731369BB29ED54C8BA7F78A218D3B560EE7C3272`. GitHub's uploaded asset digest and size match the local package.
- Download [v0.1.14](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.14).

## v0.1.13 — static PE file inspector

- Wired the Scanner route to a working user-selected local file inspector for `.exe`, `.dll`, and `.sys` files up to 256 MiB.
- Computes SHA-256 as a stream and parses bounded PE architecture, timestamp, section count, writable+executable section count, and embedded certificate-table presence.
- File is never executed/uploaded/modified/persisted by this feature. Certificate presence is not trust verification and the page makes no malware verdict.
- Release build: 0 warnings/errors; 112 tests passed. Package hash matches GitHub, and desktop/service launch plus graceful close passed. Native file-picker click-through remains manual.
- Package: `DownpourNext-win-x64-0.1.13.zip` (196,734,379 bytes); SHA-256 `72AB2B9204FF110962091DF08BA4103FDCF2E6E3A080C6DE3230A5AE3376F6FD`.
- Download [v0.1.13](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.13). Unsigned portable build; not full scanner parity. See [`FILE_INSPECTOR.md`](FILE_INSPECTOR.md).

## v0.1.12 — repair in-app update apply and recovery

- Fixed the portable update's Windows directory containment check and moved file replacement into a separate self-contained `Downpour.UpdateHelper.exe` outside the package directory.
- Update failures now show their concrete exception detail and write `%LOCALAPPDATA%\DownpourNext\updates\last-update-error.txt`. Safe failed staging can be cleared and retried.
- Added regression checks for trailing-separator roots and sibling-prefix escapes.
- Full Release build: 0 warnings/errors; 107 tests passed. A disposable v0.1.11-to-v0.1.12 apply updated the desktop, service, and helper hashes and relaunched successfully.
- Existing v0.1.10/v0.1.11 users must manually extract v0.1.12 once; future updates use the standalone helper.
- Package: `DownpourNext-win-x64-0.1.12.zip` (196,706,743 bytes); SHA-256 `C696A091F78E43EA1B663716B25DEF0500533342E22C79F1C0554575D7B19FA5`.
- Download [v0.1.12](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.12). Unsigned portable build; GitHub's digest is not a publisher signature. See [`UPDATES.md`](UPDATES.md).

## v0.1.11 — local software inventory and KEV candidate review

- Added a working Vulnerabilities route with bounded machine/current-user uninstall-key inventory and explicit software refresh/search.
- Added cautious local name candidates from the CISA KEV catalog; generic/vendor-only names and non-terminal product phrases are excluded. Rows are clearly leads only because the catalog match does not prove the installed product/version is affected.
- Inventory reads only display name/version/publisher and the SystemComponent filter flag. It does not collect paths/uninstall commands or modify the system; a bounded current-user-restricted output-only pipe feeds the desktop.
- Release build: 0 warnings/errors; 105 tests passed. Packaged desktop/service startup and graceful shutdown smoke check passed. Native page click-through remains manual.
- Package: `DownpourNext-win-x64-0.1.11.zip` (156,671,185 bytes); SHA-256 `F6745C6FBFA45736D7575F93326B838429430F288588D6E2DB0B56BBD7E8855B`.
- Download [v0.1.11](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.11). Unsigned portable build; GitHub's digest is not a publisher signature. See [`THREAT_INTELLIGENCE.md`](THREAT_INTELLIGENCE.md).

## v0.1.10 — one-click portable updates

- Added a dashboard **Update Downpour** control beside the online/offline sensor status. It checks the latest stable release from the fixed public Downpour Next repository and stages a newer version for app restart.
- The updater validates repository/tag/asset/type and GitHub-published SHA-256, restricts redirects, bounds download/archive size, rejects traversal/reparse entries, hashes staged files, waits for the desktop and bundled service to exit, uses best-effort backup rollback, and restarts.
- Both portable launchers start the desktop directly so the desktop owns and shuts down its bundled sensor service during updates. User state remains in `%LOCALAPPDATA%\DownpourNext`.
- Release build: 0 warnings/errors; 97 tests passed. Packaged desktop startup and graceful shutdown smoke check passed; native update-button click-through remains manual.
- Package: `DownpourNext-win-x64-0.1.10.zip` (156,615,827 bytes); SHA-256 `FA9F4A17BD953BB53CD8D5F60F81A604DE12D88A50F66A76D0F1635E7396B7FA`.
- Download [v0.1.10](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.10). Unsigned portable development build; GitHub's digest is not a publisher signature. See [`UPDATES.md`](UPDATES.md).

## v0.1.9 — on-demand EPSS enrichment

- Added a user-triggered single-CVE FIRST EPSS lookup from selected CISA KEV rows; it sends only that public CVE ID and does not bulk-upload/download the catalog.
- Fixed HTTPS host/path with redirects disabled, 10s deadline, 64 KiB response cap, strict JSON/identifier/value/date validation, and 24h in-memory reuse. UI shows probability, percentile, score date, and retrieval time.
- The page states that EPSS is a population-level 30-day estimate, not confirmation that this device has affected software. Local product matching and NVD/CVSS/CPE remain outstanding.
- Release build: 0 warnings/errors; 87 tests passed. A live read-only API sample matched the parser contract.
- Package: `DownpourNext-win-x64-0.1.9.zip`; SHA-256 `F89088E619E048ADAF762DA25E25299EC5A2E362B7D6B8523C3A32F3623BAB96`.
- Download from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.9). Unsigned portable test build; not full v29 parity.

## v0.1.8 — bounded Windows event push subscriptions

- Added future-event subscriptions for the fixed Windows Event Log allow-list, alongside the existing 15-second polling fallback.
- Push handling uses a 512-record nonblocking queue, 150 ms coalescing window, batches capped at 256, and record-ID deduplication. Subscription failures and cumulative queue loss are surfaced as health warnings.
- Individual Security 4625 push records are discarded; the five-minute bounded threshold aggregate remains the only 4625 finding.
- Release build: 0 warnings/errors; 74 tests passed. Service smoke check opened watchers for 7/7 channels; polling could read 6/7 on this machine. Actual event generation was not forced in automated tests.
- Package: `DownpourNext-win-x64-0.1.8.zip`; SHA-256 `472BCDB927686643976765550638D333795EE34D2A9D1C5D7833A022F28FABAD`.
- Download the unsigned portable test build from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.8). It is not an installer or full v29 parity claim.

## v0.1.7 — bounded cross-channel alert correlation

- Added two cautious alert patterns: service-install evidence across System/Security within two minutes and log-clear evidence across those channels within ten minutes.
- Alerts and metadata-only investigation export now show deterministic, one-to-one evidence links and state plainly that temporal proximity does not prove a shared actor or action. Individually suppressed rows are excluded.
- Investigation export schema is now version 2. Release build: 0 warnings/errors; 70 tests passed.
- Package: `DownpourNext-win-x64-0.1.7.zip`; SHA-256 `106C09CB9DFCD4506000C709433991395AEF41FA13FBF1EAF57F4C42EA1963C5`.
- Download the unsigned portable test build from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.7). This is not a full v29 parity claim.

## v0.1.6 — local investigation export

- Added the Alerts page's user-selected JSON investigation export using the Windows save picker.
- Export contains up to 512 validated alert metadata rows and health warnings. It revalidates the alert snapshot, excludes event bodies/user content, HTML-escapes serialized values, and refuses output over 1 MiB.
- Release build: 0 warnings/errors; 65 tests passed. Archive: `DownpourNext-win-x64-d305c2a.zip`; SHA-256 `F9FA96476CD3FF082F0353EE9B4F0BD25198E8FE91894E76E7C5BC7222E0010B`.
- Download from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.6). This remains an unsigned portable development build and does not claim full v29 parity.

## v0.1.5 — persistent false-positive rules

- Added false-positive confirmation and re-arm actions in Alerts. Three explicit confirmations of the same fixed channel/provider/event-ID rule suppress matching current and future alerts. Re-arming removes the rule and reopens only rows that it auto-suppressed; individual suppression remains independent.
- Added retry-safe confirmation/re-arm request records, bounded to 10,000 rows / 30 days, and automatic alert DB migration from schema v1 to v2.
- Fingerprints use fixed catalog metadata only. Event message text is neither collected nor analyzed.
- Release build: 0 warnings/errors; 63 tests passed. Package: `DownpourNext-win-x64-85ba7d2.zip`, SHA-256 `E3578121CE3C22B2B54CC7C87B44D7D2F0782C0AF6CC85401DADD8705E86B396`.
- Download the unsigned portable development build from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.5). This release is not an installer or full v29 parity claim.

## v0.1.4 — persistent event alerts and local triage

- Added service-side SQLite persistence for allow-listed event observations with SHA-256 IDs based on event record identity, deduplication across repeated polling, 30-day retention, and a 10,000-alert cap.
- Added five-minute bucket deduplication for aggregated 4625 failed-logon bursts; occurrence counts track the observed maximum rather than adding every repeated poll.
- Added a dedicated Alerts route with source/record evidence, severity filters, and local acknowledge, suppress, and reopen controls. Suppression affects only one alert record.
- Added a separate 1 KiB strict-schema local control pipe with expected-state checks and idempotent request IDs. It cannot request OS changes or command execution.
- Release build: 0 warnings/errors; 59 tests passed. BAT smoke check started both executables and confirmed alert DB creation.
- Archive: `DownpourNext-win-x64-5427953.zip`; SHA-256: `A354894D66DA335DE205CE86F37407D538D7DB133AF3AED5D604F558FEC50A5A`; downloadable from [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.4).
- This remains an unsigned portable development build. Broader v29 detection/correlation, Sigma/AMSI, Sysmon/ETW, system-changing actions, and installer are still outstanding.

## v0.1.3 — runnable Windows x64 package

- Added a self-contained portable Windows x64 package with `Downpour.Desktop.exe`, the bundled local sensor service, a BAT launcher, a CMD launcher, and a portable readme.
- Added the working read-only Windows Services inventory page with service state, startup type, search, and a separate bounded service IPC channel.
- The desktop EXE starts and connects to the bundled service in the tested local package. No separate .NET runtime is required.
- Release build: 0 warnings/errors. Test suite: 54 passed. Direct EXE smoke check kept the UI alive and found its bundled service process.
- Archive: `DownpourNext-win-x64-ce0bcd9.zip`; SHA-256: `915439E1ECAAABD60DE8D3FE1FC83FF7C2C68BBEEC6F3D14677F1D724DE5C9C7`.
- This is an unsigned portable development build, not an installer or a claim of full v29 parity. System-changing security and driver actions are not available yet.

## Unreleased

- Added persistent false-positive rule review: three explicit confirmations for the same fixed channel/provider/event-ID fingerprint suppress future matching alert rows; Re-arm removes that rule and reopens only rows it suppressed. Added schema-v1-to-v2 migration and retry-safe confirmation audit records. This never inspects event message text and does not perform OS actions.
- Added a service-side SQLite operation journal with schema versioning, transactional state/event writes, path-free object IDs, replay-safe event IDs, constrained transitions, restart-visible pending recovery, protected current-user/SYSTEM state directory, and append-only event triggers. It does not authorize or execute system actions.
- Restricted system, network, and driver telemetry pipes to the sensor service's current Windows account and LocalSystem; all servers remain one-way from service to desktop.
- Added `Start-Downpour-Next.bat` for direct desktop launch. The desktop launches the bundled sensor service when needed.
- Added service-backed Windows Event Log sensing for 35 fixed v29 event/channel pairs across seven channels, with bounded metadata-only IPC, per-source health, severity/search filters, and five-minute Security 4625 burst aggregation.
- Product parity includes explicit, audited, recoverable system actions; this is not intended to remain read-only. Before enabling them, add the isolated installed-service identity and a narrow verified action broker.

## v0.1.2-preview — 2026-10-04

Published at [GitHub Releases](https://github.com/christiand0797/downpour-next/releases/tag/v0.1.2-preview). Download `DownpourNext-win-x64-preview-v012.zip` to test the self-contained x64 bundle; SHA-256: `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`.

- Launching `Downpour.Desktop.exe` now starts the bundled read-only sensor service when no instance is available and shuts down only the child process it owns when the window closes.
- Dashboard, Processes, Drivers, and Network clarify that the desktop app can be running while local sensor telemetry is offline. A healthy dashboard snapshot is labeled `ONLINE`; this describes local telemetry, not internet access.
- Process inventory now carries up to 512 bounded rows instead of eight. The provider filters the Windows PID 0 `Idle` pseudo-process so valid snapshots are not rejected.
- Oversized local snapshot pipe payloads are treated as unavailable data. The client never displays fabricated readings.
- Verification: Release build 0 warnings/errors; 22 tests pass; direct-EXE smoke check confirmed bundled-service startup and graceful shutdown. Portable ZIP: `DownpourNext-win-x64-preview-v012.zip`, SHA-256 `A8E51B054DE44956B9959B74F6E92878987470F41015273892EE24964E2EF5C3`.

## v0.1.1-preview

- Added a self-contained x64 portable desktop/service bundle with a CMD launcher and the advisory CISA KEV catalog.
- Added the crescent-and-storm UI, live CPU/memory gauges, local snapshot IPC, initial route inventory, and the first threat-intelligence cache.
- The full feature-parity map and security limitations are documented in [`FEATURE_PARITY.md`](FEATURE_PARITY.md) and [`SECURITY_MODEL.md`](SECURITY_MODEL.md).
