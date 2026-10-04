# Visual references and dashboard graph notes

## Direction

Downpour keeps its own navigation and information structure. The supplied images guide the storm atmosphere, crescent focal point, dark surfaces, crisp neon accents, compact gauges, and readable data visualization. Task Manager OG is used as a measurement and graph reference only; its layout is not copied.

## User-supplied UI inspiration set

The eight attachments in the design request were reviewed as one mood board. Two identical orange/pink dial images were supplied (#7 and #8).

| Reference | Useful visual cues carried into Downpour |
|---|---|
| #1 | Dense system overview, separate analysis panels, restrained cyan/magenta data accents |
| #2 | Cyan-violet luminous surfaces, simple ring metrics, layered histories |
| #3 | Reusable gauge and graph vocabulary, clear component boundaries, consistent spacing |
| #4 | Structured technical views with stable alignment and explicit section hierarchy |
| #5 | A central instrument-like visual with small, legible supporting measurements |
| #6 | Cool blue concentric gauges, dark negative space, high-contrast numeric readouts |
| #7 | Warm amber/red states for caution and critical indicators, distinct from the normal cyan palette |
| #8 | Duplicate of #7; no additional visual requirement |

The application uses native WinUI controls, with a generated night-rain background image, translucent panels, live circular CPU/memory gauges, and CPU/memory history. The rain overlay is limited to the active window and pauses when the window is deactivated.

## Task Manager OG graph analysis

The official [TMOG site](https://tmog.org/) describes a live system summary with CPU, top processes, memory, disk, network, and energy; per-logical-processor CPU graphs; memory pressure/composition/history; network throughput/history/totals; and energy/thermal trends. It also explicitly distinguishes measured zero from unavailable data and leaves gaps when measurements stop.

Applied here:

- Current CPU and physical-memory use have circular gauges plus a rolling history chart.
- The chart uses actual service samples, carries a maximum of 60 points, and does not interpolate a missing value.
- Offline or unavailable telemetry displays an explicit state instead of a plausible zero.
- The dashboard calls out that detection and response are not connected; it never fabricates alert counts.
- Process bars compare each displayed working set with the largest displayed process and are labeled as relative.

Still to implement before matching the depth of a full performance instrument: per-core CPU history, disk throughput/activity, network bytes-per-second and per-interface totals, GPU utilization/memory, thermal sensors, power/energy attribution, memory composition/pressure, time-range controls, and history recording/replay. Each must come from a real provider and expose sensor availability.

## Source audit: Downpour v29 driver capability

The original code contains defensive driver auditing and change monitoring:

- `advanced_defense_suite.py` contains `KernelDriverAuditor`, which enumerates loaded kernel modules, checks known vulnerable driver names, flags user-writable locations, and attempts signature checks.
- `downpour_v29_titanium.py` checks loaded-driver paths for Temp, AppData, Downloads, and Public locations; the `DriverMonitor` notes in `docs/CHANGELOG.md` describe a System32 driver baseline/change monitor and a BYOVD name list.
- `docs/MODULE_MAP.md` maps `persistence_watchers.py` to a new-driver/BYOVD monitor. The existing Services route description includes service and driver inventory/change monitoring.
- A targeted search did not find a driver package install, update, reinstall, or removal workflow in the original UI/module map. Downpour Next's dedicated Drivers route is an additive feature; package lifecycle actions still need their own security design.

The current Drivers view is a live, read-only list of loaded kernel modules and path classification. It does not currently verify Authenticode signatures, enumerate the Driver Store package catalog, or alter devices/drivers.
