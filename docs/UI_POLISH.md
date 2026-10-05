# Dashboard visual and navigation pass

This slice uses the existing Downpour storm-and-crescent identity and the supplied dark neon dashboard references: near-black blue surfaces, legible cool-gray text, restrained cyan outlines, and cyan/violet data accents. It retains Downpour's own security-monitoring routes and hierarchy.

## Findings from the packaged app

- The 33 route entries were flattened into a narrow icon rail. Reused glyphs made unrelated destinations look like duplicate tabs, and compact mode hid every route name.
- The four dashboard fact cards had fixed widths, leaving a large unused region on wide displays.
- Rain streaks and the landscape showed through text panels strongly enough to compete with the labels.
- The resource graph and circular gauges used the available dashboard width well and are retained.

## Changes

- The dashboard remains directly accessible; the other routes sit in six labeled expandable sections. Monitoring opens by default because it contains the connected live inventory views.
- Route IDs are checked case-insensitively before insertion so a duplicate capability record does not create a second visible destination.
- The all-window storm stays behind the interface with a darker scrim. Shared surface/accent resources give the dashboard cards more contrast while preserving the visible night/rain motif.
- The four live system fact cards use equal-width columns across the available dashboard area.
- The dashboard scroll container disables horizontal scrolling and stretches its page content so a wide metric row cannot push its final cards beyond the viewport.

## Verification

- `dotnet build Downpour.slnx -c Release --no-restore`: passed, 0 warnings and 0 errors.
- Circular gauges now draw a dense sampled arc on the same center/radius as the track, starting at 12 o'clock, with explicit 0%, 100%, and unknown behavior. The dashboard percentage axis and oldest/now labels no longer misuse x-axis captions.
- Dashboard and network lines use a subtle two-pass neon stroke; a latest-point marker appears only when the newest sample is real. Network plot includes a live peak-rate scale label and oldest/now axis.
- Fixed a native WinUI chart crash: `Polyline.Points` collections cannot be shared by multiple Shapes. Glow and crisp strokes now receive independent point collections; the same ownership rule is used on dashboard, network, and Performance plots. Snapshot exceptions clear live UI state and create a visible chart gap.
- Added the Monitoring > Performance route, backed by the local sensor service: CPU and memory gauges, 40-point/two-minute history, CPU topology count, process count, physical memory used/available/total, and top 10 working sets with each row's process/thread count. Manual refresh, sampling pause/resume, and a Windows save-picker CSV export of bounded timestamped CPU, memory, and network history are available. Error/offline paths clear stale telemetry and insert graph gaps.
- Performance now includes live system CPU, physical memory, system commit, OS-volume usage, combined active-adapter receive/send, and system-wide physical-disk read/write gauges. Separate network and disk throughput histories use byte-per-second units, preserve unavailable gaps, and scale their gauges to the rolling two-minute peak. Disk throughput comes from locale-independent `PdhAddEnglishCounterW` counters for `PhysicalDisk(_Total)\Disk Read Bytes/sec` and `Disk Write Bytes/sec`; PDH rates remain unknown until Windows has two samples and whenever the counters cannot be read. The [PDH formatted-counter API](https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhgetformattedcountervalue) documents that rate counters require two collected values; see also [collecting performance data](https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data). Commit usage comes from [GetPerformanceInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getperformanceinfo) system-wide `CommitTotal`/`CommitLimit` page counts converted using `PageSize`; it does not treat process-limited paging-file values as system-wide. CSV includes CPU, memory, commit, network, and disk readings, with blank cells for unavailable values.
- The initial native launch exposed a WinUI exception because two chart `Polyline` shapes shared one mutable `PointCollection`. Dashboard, network, and Performance plots now give each shape an independent collection. The exception path clears stale live readings and inserts a gap.
- Per-process CPU is sampled by the service from cumulative process CPU-time deltas and a monotonic elapsed interval, normalized to total logical-processor capacity (0–100%). A process row reports unknown until two accessible samples exist; process start time is compared so reused PIDs reset instead of inheriting the prior process's delta. Client validation rejects out-of-range CPU values. Process inventory and Performance working-set rows display the reading. Per-core CPU/history, per-process CPU history/sorting, pagefile storage utilization, and configurable sampling/thresholds remain open. GPU, clocks, temperature, fan, and power require supported hardware sources and remain unknown when unavailable.
- Live process, adapter, TCP connection, and Performance working-set lists now reconcile rows by stable identity and update observable properties in place. They no longer clear and repopulate every visible row on each refresh; dashboard offline state also retains the last chart while clearly labeling it stale/unavailable. Unchanged gauge values skip path regeneration.
- The v0.1.14 baseline was rebuilt and published as a self-contained portable ZIP. GitHub's reported digest and size match the local archive; the package desktop launched and its bundled service child was confirmed running. This pass adds live disk throughput and incremental refresh updates; v0.1.15 packaging/checks are in progress.
- v0.1.14 baseline build had 0 warnings and 0 errors; 117 tests passed. Targeted Performance/provider tests pass with the disk counter case added. `artifacts/desktop-downpour-latest.png` is a valid dashboard capture. Native Performance route/save-picker click-through remains open, along with narrow/high-DPI layout and Settings interaction.
- The before screenshot is `artifacts/downpour-ui-before.png`; it is local-only. Do not treat it as a post-change capture.
