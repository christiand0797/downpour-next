using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Downpour.Service;

/// <summary>
/// Maps local TCP listener endpoints to owning process ids from the OS TCP owner tables and resolves a bounded
/// number of image names. Read-only: it reads one table per address family and never changes process state.
/// </summary>
internal static class TcpOwnerLookup
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidListener = 3;
    private const uint ErrorInsufficientBuffer = 122;
    private const int MaximumNameLookups = 128;
    private const int ProcessQueryLimitedInformation = 0x1000;

    /// <summary>Endpoint keys match <see cref="IPEndPoint.ToString"/> for the family, e.g. <c>127.0.0.1:445</c> or <c>[::]:443</c>.</summary>
    public static IReadOnlyDictionary<string, int> CaptureListenerOwners()
    {
        var owners = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        ReadTable(owners, AfInet);
        ReadTable(owners, AfInet6);
        return owners;
    }

    /// <summary>Resolves the image file name for a pid, cached per capture. Null when the process cannot be opened.</summary>
    public static string? ProcessName(int processId, Dictionary<int, string?> cache)
    {
        if (processId <= 0) return null;
        if (cache.TryGetValue(processId, out var cached)) return cached;

        string? name = null;
        if (cache.Count < MaximumNameLookups)
        {
            var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    var buffer = new StringBuilder(260);
                    var size = buffer.Capacity;
                    if (QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0)
                    {
                        var path = buffer.ToString(0, size);
                        var separator = path.LastIndexOf('\\');
                        name = separator >= 0 ? path[(separator + 1)..] : path;
                        if (name.Length is 0 or > 256) name = null;
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
        }

        cache[processId] = name;
        return name;
    }

    private static void ReadTable(Dictionary<string, int> owners, int family)
    {
        var size = 0;
        if (GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TcpTableOwnerPidListener, 0) != ErrorInsufficientBuffer || size <= 0)
            return;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidListener, 0) != 0) return;
            var count = Marshal.ReadInt32(buffer);
            var rowSize = family == AfInet ? 24 : 56;
            if (count < 0 || 4L + (long)count * rowSize > size) return;

            for (var index = 0; index < count; index++)
            {
                var row = IntPtr.Add(buffer, 4 + index * rowSize);
                int port;
                int processId;
                string address;
                if (family == AfInet)
                {
                    // MIB_TCPROW_OWNER_PID: state, local address, local port, remote address, remote port, pid.
                    // The row stores the address in network byte order; round-trip the raw bytes instead of
                    // relying on IPAddress(long) ordering.
                    address = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(row, 4))).ToString();
                    port = (ushort)IPAddress.NetworkToHostOrder((short)(Marshal.ReadInt32(row, 8) & 0xFFFF));
                    processId = Marshal.ReadInt32(row, 20);
                }
                else
                {
                    // MIB_TCP6ROW_OWNER_PID: 16-byte local address, scope id, local port, remote 16 bytes,
                    // remote scope id, remote port, state, pid.
                    var bytes = new byte[16];
                    Marshal.Copy(row, bytes, 0, 16);
                    address = new IPAddress(bytes).ToString();
                    port = (ushort)IPAddress.NetworkToHostOrder((short)(Marshal.ReadInt32(row, 20) & 0xFFFF));
                    processId = Marshal.ReadInt32(row, 52);
                }

                if (port <= 0 || processId <= 0) continue;
                owners[family == AfInet ? $"{address}:{port}" : $"[{address}]:{port}"] = processId;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
