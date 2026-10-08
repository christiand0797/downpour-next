namespace Downpour.Service;

/// <summary>Schedules host-isolation cleanup independently of the desktop lifetime.</summary>
public interface IIsolationReleaseScheduler
{
    /// <summary>Registers the release; returns null on success or the reason it could not be scheduled.</summary>
    string? Schedule(DateTimeOffset releaseAtUtc);

    void Cancel();
}

/// <summary>
/// Windows Task Scheduler implementation (documented Schedule.Service COM API). Registers a one-time task that runs this
/// service binary with the fixed switch <c>--release-isolation</c> at the expiry time, as the current user with highest
/// privileges (S4U, so it runs whether or not the user is signed in), and catches up as soon as possible if the PC was
/// asleep or off. No shell, script, or arbitrary command line is involved.
/// </summary>
public sealed class TaskSchedulerIsolationRelease : IIsolationReleaseScheduler
{
    public const string FolderName = "DownpourNext";
    public const string TaskName = "ReleaseHostIsolation";
    public const string ReleaseSwitch = "--release-isolation";

    public string? Schedule(DateTimeOffset releaseAtUtc)
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrEmpty(executable) || !File.Exists(executable))
            return "The service executable path is unknown, so an automatic release cannot be scheduled.";
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: false);
            if (type is null) return "Windows Task Scheduler is not available.";
            dynamic service = Activator.CreateInstance(type)!;
            service.Connect();
            dynamic folder = Folder(service, create: true);
            dynamic definition = service.NewTask(0);
            definition.RegistrationInfo.Description = "Ends Downpour Next host isolation at its expiry time, even if Downpour is not running.";
            definition.Principal.UserId = $@"{Environment.UserDomainName}\{Environment.UserName}";
            definition.Principal.LogonType = 2;   // TASK_LOGON_S4U: runs whether or not the user is signed in
            definition.Principal.RunLevel = 1;    // TASK_RUNLEVEL_HIGHEST: firewall rules need administrator rights
            definition.Settings.StartWhenAvailable = true;
            definition.Settings.DisallowStartIfOnBatteries = false;
            definition.Settings.StopIfGoingOnBatteries = false;
            definition.Settings.ExecutionTimeLimit = "PT5M";
            definition.Settings.RestartInterval = "PT1M";
            definition.Settings.RestartCount = 3;
            definition.Settings.DeleteExpiredTaskAfter = "PT0S";
            dynamic trigger = definition.Triggers.Create(1); // TASK_TRIGGER_TIME
            var local = releaseAtUtc.ToLocalTime();
            trigger.StartBoundary = local.ToString("yyyy-MM-dd'T'HH:mm:ss");
            trigger.EndBoundary = local.AddDays(2).ToString("yyyy-MM-dd'T'HH:mm:ss");
            dynamic action = definition.Actions.Create(0); // TASK_ACTION_EXEC
            action.Path = executable;
            action.Arguments = ReleaseSwitch;
            action.WorkingDirectory = Path.GetDirectoryName(executable);
            folder.RegisterTaskDefinition(TaskName, definition, 6 /* CREATE_OR_UPDATE */, null, null, 2 /* S4U */);
            return null;
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or UnauthorizedAccessException or InvalidOperationException
            or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return $"Windows Task Scheduler refused the automatic release ({ex.Message.Trim()}). Isolation needs Downpour to run as administrator.";
        }
    }

    public void Cancel()
    {
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: false);
            if (type is null) return;
            dynamic service = Activator.CreateInstance(type)!;
            service.Connect();
            dynamic? folder = Folder(service, create: false);
            folder?.DeleteTask(TaskName, 0);
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or UnauthorizedAccessException or InvalidOperationException
            or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            // Nothing scheduled, or already removed; the task deletes itself after running.
        }
    }

    private static dynamic? Folder(dynamic service, bool create)
    {
        dynamic root = service.GetFolder("\\");
        try { return service.GetFolder("\\" + FolderName); }
        catch (System.Runtime.InteropServices.COMException) when (create) { return root.CreateFolder(FolderName, null); }
        catch (System.Runtime.InteropServices.COMException) { return null; }
    }
}
