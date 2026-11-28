using System.Runtime.InteropServices;

namespace Downpour.Service;

public sealed record ScheduledTaskActionOutcome(bool Succeeded, string ResultCode, string Message);

public interface IScheduledTaskBackend
{
    ScheduledTaskActionOutcome SetEnabled(string taskPath, bool enabled);
    ScheduledTaskActionOutcome Delete(string taskPath);
}

/// <summary>
/// Task Scheduler COM adapter. Everything here runs read-after-write: a change Windows did not apply is reported
/// as a failure rather than a success, so the UI never claims a state the machine is not in.
/// </summary>
public sealed class WindowsScheduledTaskBackend : IScheduledTaskBackend
{
    private const int FileNotFound = unchecked((int)0x80070002);
    private const int AccessDenied = unchecked((int)0x80070005);

    public ScheduledTaskActionOutcome SetEnabled(string taskPath, bool enabled)
    {
        object? scheduler = null, folder = null, task = null;
        try
        {
            (scheduler, folder, task) = OpenTask(taskPath, out _);
            dynamic dynamicTask = task;
            dynamicTask.Enabled = enabled;
            if ((bool)dynamicTask.Enabled != enabled)
                return new(false, "state-not-applied", "Windows accepted the request but reports a different enabled state.");
            return new(true, enabled ? "task-enabled" : "task-disabled",
                enabled ? "The task is enabled and can run on its triggers." : "The task is disabled and will not run on its triggers.");
        }
        catch (COMException ex)
        {
            return MapFailure(ex);
        }
        catch (Exception ex) when (ex is InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return new(false, "windows-error", "Task Scheduler returned an unexpected response.");
        }
        finally
        {
            Release(task, folder, scheduler);
        }
    }

    public ScheduledTaskActionOutcome Delete(string taskPath)
    {
        object? scheduler = null, folder = null, task = null;
        try
        {
            (scheduler, folder, task) = OpenTask(taskPath, out var leaf);
            dynamic dynamicFolder = folder;
            dynamicFolder.DeleteTask(leaf, 0);

            try
            {
                dynamicFolder.GetTask(leaf);
                return new(false, "delete-not-applied", "Windows still returns the task after deletion.");
            }
            catch (COMException ex) when (ex.HResult == FileNotFound)
            {
                return new(true, "task-deleted", "The task was removed from Task Scheduler.");
            }
        }
        catch (COMException ex)
        {
            return MapFailure(ex);
        }
        catch (Exception ex) when (ex is InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return new(false, "windows-error", "Task Scheduler returned an unexpected response.");
        }
        finally
        {
            Release(task, folder, scheduler);
        }
    }

    private static (object scheduler, object folder, object task) OpenTask(string taskPath, out string leaf)
    {
        var lastSeparator = taskPath.LastIndexOf('\\');
        var folderPath = lastSeparator <= 0 ? "\\" : taskPath[..lastSeparator];
        leaf = taskPath[(lastSeparator + 1)..];

        var schedulerType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)
            ?? throw new COMException("Task Scheduler is not available.", FileNotFound);
        dynamic scheduler = Activator.CreateInstance(schedulerType)!;
        scheduler.Connect();
        object folder = scheduler.GetFolder(folderPath);
        dynamic dynamicFolder = folder;
        object task = dynamicFolder.GetTask(leaf);
        return (scheduler, folder, task);
    }

    private static ScheduledTaskActionOutcome MapFailure(COMException ex) => ex.HResult switch
    {
        FileNotFound => new(false, "task-not-found", "The task no longer exists. Refresh the list and try again."),
        AccessDenied => new(false, "access-denied", "Windows denied the change. Run Downpour as administrator or check the task's permissions."),
        _ => new(false, "windows-error", $"Task Scheduler returned 0x{ex.HResult:X8}."),
    };

    private static void Release(object? task, object? folder, object? scheduler)
    {
        foreach (var item in new[] { task, folder, scheduler })
        {
            if (item is not null && Marshal.IsComObject(item))
            {
                try { Marshal.FinalReleaseComObject(item); } catch (Exception) { }
            }
        }
    }
}

/// <summary>
/// Policy gate for scheduled-task changes. Paths are validated and Windows-owned or Downpour-owned tasks are
/// immutable from the product before any COM call is made.
/// </summary>
public sealed class ScheduledTaskActionExecutor
{
    private readonly IScheduledTaskBackend _backend;

    public ScheduledTaskActionExecutor(IScheduledTaskBackend backend) => _backend = backend;

    public ScheduledTaskActionExecutor() : this(new WindowsScheduledTaskBackend()) { }

    public ScheduledTaskActionOutcome SetEnabled(string taskPath, bool enabled) =>
        !IsValidTaskPath(taskPath)
            ? new(false, "invalid-task-path", "Task path is not a valid Task Scheduler path.")
            : ProtectedReason(taskPath) is { } reason
                ? new(false, "denied-protected-task", reason)
                : _backend.SetEnabled(taskPath, enabled);

    public ScheduledTaskActionOutcome Delete(string taskPath) =>
        !IsValidTaskPath(taskPath)
            ? new(false, "invalid-task-path", "Task path is not a valid Task Scheduler path.")
            : ProtectedReason(taskPath) is { } reason
                ? new(false, "denied-protected-task", reason)
                : _backend.Delete(taskPath);

    /// <summary>A full task path such as \Vendor\Nightly backup, no trailing separator and no traversal.</summary>
    public static bool IsValidTaskPath(string? taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath) || taskPath.Length is < 3 or > 512) return false;
        if (taskPath[0] != '\\' || taskPath[^1] == '\\') return false;
        if (taskPath.Contains("..", StringComparison.Ordinal)) return false;
        if (taskPath.Any(c => c < ' ' || c == '\u007f')) return false;

        var segments = taskPath[1..].Split('\\');
        return segments.All(segment => segment.Length is > 0 and <= 255 && segment.Trim() == segment);
    }

    /// <summary>Returns why a task is immutable, or null when the product may manage it.</summary>
    public static string? ProtectedReason(string taskPath)
    {
        if (taskPath.StartsWith("\\Microsoft\\Windows\\", StringComparison.OrdinalIgnoreCase))
            return "Windows-owned tasks under \\Microsoft\\Windows are protected because disabling or removing the wrong one can stop updates, Defender, or maintenance.";
        if (taskPath.StartsWith("\\Downpour\\", StringComparison.OrdinalIgnoreCase))
            return "Downpour's own scheduled tasks are managed by the product and cannot be changed here.";
        return null;
    }
}
