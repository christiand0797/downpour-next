using Downpour.Core;
using Downpour.Fixer;

// Downpour.Fixer: the only part of Downpour that runs as administrator. It accepts exactly three commands built by the
// desktop (apply catalog fixes, undo a backup it wrote itself, install Windows updates), validates them before doing
// anything, writes every result and an audit line into its administrator-only folder, and exits. Windows shows its own
// consent prompt each time it starts.
const int Ok = 0, Refused = 2, Failed = 3;

if (!FixerProtocol.IsValidCommand(args, out var error))
    return Refused;

var verb = args[0];
var requestId = args[1];
var argument = args[2];

// No job may run forever: updates get three hours, setting changes five minutes.
var limit = verb == FixerProtocol.Updates ? TimeSpan.FromHours(3) : TimeSpan.FromMinutes(5);
_ = Task.Delay(limit).ContinueWith(_ =>
{
    try
    {
        FixerStore.Write(FixerProtocol.ResultPath(requestId), new FixRunResult(verb, null, [new("timeout", false, "Stopped: the job took too long.")], false, DateTimeOffset.UtcNow));
        FixerStore.Audit(verb, requestId, "timed out");
    }
    finally { Environment.Exit(Failed); }
});

try
{
    FixerStore.Prepare();
    FixerStore.Audit(verb, requestId, $"start {argument}");
    FixRunResult result;
    switch (verb)
    {
        case FixerProtocol.Apply:
        {
            var backupId = Guid.NewGuid().ToString("N");
            result = HardeningFixes.Apply(new FixHost(), argument.Split(','), backupId, DateTimeOffset.UtcNow, out var backup);
            if (backup.Entries.Count > 0) FixerStore.Write(FixerProtocol.BackupPath(backupId), backup);
            else result = result with { BackupId = null };
            break;
        }
        case FixerProtocol.Undo:
        {
            // Only a backup this fixer wrote into its protected folder can be restored.
            var backup = FixerProtocol.ReadJson<FixBackup>(FixerProtocol.BackupPath(argument));
            if (backup is null || backup.BackupId != argument)
            {
                result = new FixRunResult(verb, argument, [new("undo", false, "That backup was not found.")], false, DateTimeOffset.UtcNow);
                break;
            }
            result = HardeningFixes.Undo(new FixHost(), backup, DateTimeOffset.UtcNow);
            if (result.Outcomes.All(o => o.Applied)) File.Move(FixerProtocol.BackupPath(argument), FixerProtocol.BackupPath(argument) + ".undone", overwrite: true);
            break;
        }
        default:
            result = WindowsUpdateInstaller.Run(argument, status => FixerStore.Write(FixerProtocol.StatusPath(requestId), status));
            break;
    }
    FixerStore.Write(FixerProtocol.ResultPath(requestId), result);
    FixerStore.Audit(verb, requestId, string.Join("; ", result.Outcomes.Select(o => $"{o.FixId}={(o.Applied ? "ok" : "failed")}")));
    return result.Outcomes.All(o => o.Applied) ? Ok : Failed;
}
catch (Exception ex)
{
    try
    {
        FixerStore.Write(FixerProtocol.ResultPath(requestId), new FixRunResult(verb, null, [new("error", false, ex.Message.Length > 300 ? ex.Message[..300] : ex.Message)], false, DateTimeOffset.UtcNow));
        FixerStore.Audit(verb, requestId, "error " + ex.GetType().Name);
    }
    catch (Exception) { }
    return Failed;
}
