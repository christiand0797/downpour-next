# Scheduled tasks

The **Scheduled tasks** route (`scheduled-tasks`, Monitoring) lists every Task Scheduler task the service can read,
including hidden tasks. It uses the same persistence capture as the Hunt route: each task is a
`PersistenceEntry` in the `ScheduledTask` category, and the scheduler-only fields travel in an optional
`PersistenceTaskDetail` that is **not** part of the baseline key or hash. Opening or acting on the page therefore
never makes a task look modified to the persistence baseline.

## What is shown

| Field | Source |
| --- | --- |
| State | Task Scheduler state: Ready, Running, Queued, Disabled, or Unknown |
| Run as / Run level | Task principal identity and whether it runs with highest privileges |
| Author / Hidden | Registration info and the hidden flag |
| Triggers | Up to 8 triggers as `type · start · enabled` |
| Next / last run | Task Scheduler wall-clock values, converted to local time |
| Last result | The scheduler's raw result code, uninterpreted |
| Action | The task's primary action (`Exec` path/arguments) as already captured for the baseline |

A task whose definition this account cannot read still appears with its state and action; properties that fail
individually stay blank. Next and last run are Task Scheduler's own values, not observed executions.

## Actions

Enable, disable, and delete are available from each row's overflow menu. They follow the DN-008 action path, not a
direct write from the desktop:

1. `ScheduledTaskActionClient` asks the service over `Downpour.ScheduledTaskActions.v1`.
2. The service verifies the pipe caller, the `ScheduledTaskActions` setting, the task path policy, and the
   protected-task list **before** anything else.
3. A preview mints a single-use, short-lived consent token bound to the operation and the exact task path. The
   desktop shows the expected effects and risks and requires an explicit confirmation; deletion also requires
   acknowledging that it cannot be undone from Downpour.
4. Execution consumes the token once, performs the COM change, re-reads the resulting state, and records every
   attempt (accepted or refused) in the action audit log. Windows records the change in its own Task Scheduler log.

Path policy: a full path (`\Folder\Task`), no traversal, no control characters, 3–512 characters. Tasks under
`\Microsoft\Windows\` and Downpour's own `\Downpour\` folder are protected from enable, disable, and delete.

Not available by design: running a task on demand, editing triggers/actions/principal, importing task XML, and
changing tasks through any other route. The table refreshes on the next sensor capture, so a just-applied change may
appear one capture later.

## Settings and privacy

The **Allow scheduled-task changes** switch (Settings → sensor settings) gates the action pipe; with it off the
service refuses both previews and execution. The setting is stored with the other sensor settings. Task names,
paths, principals, and actions stay on this machine; nothing is uploaded.

## Verification

Unit tests cover path validation, the protected list, consent single-use, deletion scope, caller denial, and the
feature switch. The COM path itself was not exercised against live tasks during development, so the first real
enable/disable/delete should be reviewed on screen; the service re-reads state and reports failure instead of
assuming success.
