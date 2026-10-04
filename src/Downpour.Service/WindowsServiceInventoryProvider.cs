using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>Bounded, read-only inventory of Windows services and their startup configuration.</summary>
public sealed class WindowsServiceInventoryProvider
{
    public const int MaximumServices = 512;
    private const int MaximumTextLength = 256;
    private const int MaximumWarningLength = 512;
    private const int MaximumPages = 16;
    private const int EnumerationBufferBytes = 256 * 1024;
    private const uint ScManagerEnumerateService = 0x0004;
    private const uint ServiceTypeAll = 0x003F;
    private const uint ServiceStateAll = 0x0003;
    private const int ScEnumProcessInfo = 0;
    private const int ErrorAccessDenied = 5;
    private const int ErrorMoreData = 234;
    private const int ErrorInsufficientBuffer = 122;
    private const uint ServiceQueryConfig = 0x0001;

    public WindowsServiceInventorySnapshot Capture()
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var warnings = new List<string>();
        var services = new List<WindowsServiceInventoryEntry>(MaximumServices);
        using var manager = OpenSCManager(null, null, ScManagerEnumerateService);
        if (manager.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            warnings.Add(error == ErrorAccessDenied
                ? "Access denied while opening the Windows Service Control Manager."
                : "Windows could not open the Service Control Manager.");
            return Snapshot(error == ErrorAccessDenied ? "Access denied" : "Unavailable", capturedAt, services, warnings);
        }

        var resumeHandle = 0;
        var pages = 0;
        var complete = false;
        var seenResumeHandles = new HashSet<int>();
        var rowSize = Marshal.SizeOf<EnumServiceStatusProcess>();
        var buffer = Marshal.AllocHGlobal(EnumerationBufferBytes);
        try
        {
            while (pages++ < MaximumPages && services.Count < MaximumServices)
            {
                var succeeded = EnumServicesStatusEx(
                    manager, ScEnumProcessInfo, ServiceTypeAll, ServiceStateAll, buffer,
                    EnumerationBufferBytes, out _, out var returned, ref resumeHandle, null);
                var error = succeeded ? 0 : Marshal.GetLastWin32Error();

                if (returned < 0 || returned > EnumerationBufferBytes / rowSize)
                {
                    warnings.Add("Windows returned an invalid service inventory page.");
                    break;
                }

                for (var index = 0; index < returned && services.Count < MaximumServices; index++)
                {
                    var rowPointer = IntPtr.Add(buffer, checked(index * rowSize));
                    var nativeRow = Marshal.PtrToStructure<EnumServiceStatusProcess>(rowPointer);
                    if (!TryReadBoundedString(nativeRow.ServiceName, buffer, EnumerationBufferBytes, out var serviceName) ||
                        !TryReadBoundedString(nativeRow.DisplayName, buffer, EnumerationBufferBytes, out var displayName) ||
                        string.IsNullOrWhiteSpace(serviceName))
                    {
                        warnings.Add("Windows returned a service entry with invalid text data.");
                        continue;
                    }

                    services.Add(new WindowsServiceInventoryEntry(
                        serviceName,
                        string.IsNullOrWhiteSpace(displayName) ? "Unknown" : displayName,
                        MapState(nativeRow.Status.CurrentState),
                        QueryStartupType(manager, serviceName)));
                }

                if (succeeded)
                {
                    complete = true;
                    break;
                }

                if (error != ErrorMoreData)
                {
                    warnings.Add(error == ErrorAccessDenied
                        ? "Access denied while enumerating Windows services."
                        : "Windows service enumeration ended before all entries could be read.");
                    break;
                }

                if (returned == 0 || !seenResumeHandles.Add(resumeHandle))
                {
                    warnings.Add("Windows service enumeration stopped because it made no progress.");
                    break;
                }
            }
        }
        catch (OutOfMemoryException)
        {
            warnings.Add("Windows service inventory could not allocate a bounded enumeration page.");
        }
        catch (Win32Exception)
        {
            warnings.Add("Windows service enumeration failed while reading the service catalog.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        if (services.Count >= MaximumServices)
            warnings.Add($"Service inventory is limited to the first {MaximumServices} entries.");
        if (!complete && warnings.Count == 0)
            warnings.Add("Windows service inventory was truncated before enumeration completed.");

        var status = complete ? "Available" : services.Count > 0 ? "Partial" : "Unavailable";
        return Snapshot(status, capturedAt, services, warnings);
    }

    private static WindowsServiceInventorySnapshot Snapshot(
        string status,
        DateTimeOffset capturedAt,
        IReadOnlyList<WindowsServiceInventoryEntry> services,
        IReadOnlyList<string> warnings) =>
        new(1, capturedAt, status, services.Count, services, warnings.Take(64).Select(BoundWarning).ToArray());

    private static string QueryStartupType(SafeServiceControlHandle manager, string serviceName)
    {
        using var service = OpenService(manager, serviceName, ServiceQueryConfig);
        if (service.IsInvalid)
            return Marshal.GetLastWin32Error() == ErrorAccessDenied ? "Access denied" : "Unknown";

        _ = QueryServiceConfig(service, IntPtr.Zero, 0, out var requiredBytes);
        var error = Marshal.GetLastWin32Error();
        if (error != ErrorInsufficientBuffer || requiredBytes < 1 || requiredBytes > 64 * 1024)
            return error == ErrorAccessDenied ? "Access denied" : "Unknown";

        var configuration = Marshal.AllocHGlobal(checked((int)requiredBytes));
        try
        {
            if (!QueryServiceConfig(service, configuration, requiredBytes, out _))
                return Marshal.GetLastWin32Error() == ErrorAccessDenied ? "Access denied" : "Unknown";

            var config = Marshal.PtrToStructure<QueryServiceConfigNative>(configuration);
            return config.StartType switch
            {
                0 => "Boot",
                1 => "System",
                2 => "Automatic",
                3 => "Manual",
                4 => "Disabled",
                _ => "Unknown"
            };
        }
        catch (ArgumentException)
        {
            return "Unknown";
        }
        finally
        {
            Marshal.FreeHGlobal(configuration);
        }
    }

    private static string MapState(uint state) => state switch
    {
        1 => "Stopped",
        2 => "Start pending",
        3 => "Stop pending",
        4 => "Running",
        5 => "Continue pending",
        6 => "Pause pending",
        7 => "Paused",
        _ => "Unknown"
    };

    private static bool TryReadBoundedString(IntPtr value, IntPtr buffer, int bufferBytes, out string result)
    {
        result = "";
        var start = buffer.ToInt64();
        var address = value.ToInt64();
        var end = start + bufferBytes;
        if (value == IntPtr.Zero || address < start || address > end - sizeof(char)) return false;

        var availableChars = (int)Math.Min(MaximumTextLength + 1L, (end - address) / sizeof(char));
        if (availableChars <= 0) return false;
        var raw = Marshal.PtrToStringUni(value, availableChars);
        if (raw is null) return false;
        var terminator = raw.IndexOf('\0');
        result = (terminator >= 0 ? raw[..terminator] : raw)[..Math.Min(MaximumTextLength, terminator >= 0 ? terminator : raw.Length)];
        return true;
    }

    private static string BoundWarning(string value) => value.Length <= MaximumWarningLength ? value : value[..MaximumWarningLength];

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenSCManagerW")]
    private static extern SafeServiceControlHandle OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "EnumServicesStatusExW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusEx(
        SafeServiceControlHandle manager,
        int infoLevel,
        uint serviceType,
        uint serviceState,
        IntPtr services,
        int bufferSize,
        out int bytesNeeded,
        out int servicesReturned,
        ref int resumeHandle,
        string? groupName);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenServiceW")]
    private static extern SafeServiceControlHandle OpenService(SafeServiceControlHandle manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryServiceConfigW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(SafeServiceControlHandle service, IntPtr configuration, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "CloseServiceHandle")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public ServiceStatusProcess Status;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigNative
    {
        public IntPtr BinaryPathName;
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    private sealed class SafeServiceControlHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceControlHandle() : base(ownsHandle: true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
}
