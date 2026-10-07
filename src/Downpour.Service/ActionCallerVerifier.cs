using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

public interface IActionCallerVerifier
{
    /// <summary>Returns null when the connected client may request actions, otherwise a denial reason.</summary>
    string? Verify(NamedPipeServerStream pipe);
}

/// <summary>
/// Accepts only the Downpour desktop that launched this service: the pipe client must be the service's parent process, its
/// image must be Downpour.Desktop.exe (and the copy in the install folder when that layout is present), and it must have
/// started before the service so a reused PID cannot pass. Until release signing exists (DN-010) this is weaker than an
/// Authenticode check; a same-user process could still drive the desktop UI (SECURITY.md, DN-008).
/// </summary>
public sealed class ParentDesktopCallerVerifier : IActionCallerVerifier
{
    public const string DesktopImageName = "Downpour.Desktop.exe";
    private readonly int? _parentId;
    private readonly string? _parentImage;
    private readonly DateTime? _parentStart;
    private readonly string? _parentError;

    public ParentDesktopCallerVerifier()
    {
        using var self = Process.GetCurrentProcess();
        var serviceStart = self.StartTime;
        var parent = ParentProcessId(self.Id);
        if (parent is null) { _parentError = "The service has no parent process."; return; }
        try
        {
            using var process = Process.GetProcessById(parent.Value);
            _parentStart = process.StartTime;
            _parentImage = ImagePath(parent.Value);
            if (_parentStart > serviceStart) { _parentError = "The parent process started after the service."; return; }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _parentError = "The parent process is not running.";
            return;
        }
        if (_parentImage is null || !Path.GetFileName(_parentImage).Equals(DesktopImageName, StringComparison.OrdinalIgnoreCase))
        {
            _parentError = "The service was not started by the Downpour desktop.";
            return;
        }
        var serviceDirectory = AppContext.BaseDirectory.TrimEnd('\\');
        var installDirectory = Path.GetFileName(serviceDirectory).Equals("service", StringComparison.OrdinalIgnoreCase)
            ? Path.GetDirectoryName(serviceDirectory)! : serviceDirectory;
        var expected = Path.Combine(installDirectory, DesktopImageName);
        if (File.Exists(expected) && !Path.GetFullPath(expected).Equals(Path.GetFullPath(_parentImage), StringComparison.OrdinalIgnoreCase))
        {
            _parentError = "The parent desktop is not the copy installed with this service.";
            return;
        }
        _parentId = parent;
    }

    public string? Verify(NamedPipeServerStream pipe)
    {
        if (_parentError is not null) return _parentError;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientId)) return "The caller could not be identified.";
        if (clientId != _parentId) return "Only the Downpour desktop that started the service may request actions.";
        try
        {
            using var process = Process.GetProcessById((int)clientId);
            if (process.StartTime != _parentStart) return "The caller's process identity changed.";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return "The caller is no longer running.";
        }
        return ImagePath((int)clientId) is { } image && image.Equals(_parentImage, StringComparison.OrdinalIgnoreCase)
            ? null : "The caller's image changed.";
    }

    private static int? ParentProcessId(int processId)
    {
        using var snapshot = CreateToolhelp32Snapshot(0x2, 0);
        if (snapshot.IsInvalid) return null;
        var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
        if (!Process32FirstW(snapshot, ref entry)) return null;
        do
        {
            if (entry.ProcessId == processId) return (int)entry.ParentProcessId;
        }
        while (Process32NextW(snapshot, ref entry));
        return null;
    }

    private static string? ImagePath(int processId)
    {
        using var handle = OpenProcess(0x1000, false, (uint)processId);
        if (handle.IsInvalid) return null;
        var buffer = new char[32_768];
        var length = (uint)buffer.Length;
        return QueryFullProcessImageNameW(handle, 0, buffer, ref length) ? new string(buffer, 0, (int)length) : null;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size, Usage, ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId, Threads, ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(SafeFileHandle snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(SafeFileHandle snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
}
