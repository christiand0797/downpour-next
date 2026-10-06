using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

/// <summary>
/// Read-only remote-access exposure (v29 RemoteAccessDetector.scan): RDP configuration, TCP listeners and
/// established connections on remote-access ports with their owning process names, and running remote-access tools.
/// Collects process names only, never command lines.
/// </summary>
public sealed class RemoteAccessProvider
{
    internal const int MaximumRows = 512;
    private const int AfInet = 2, AfInet6 = 23, TcpTableOwnerPidAll = 5, StateListen = 2, StateEstablished = 5;
    private const int Ipv4RowSize = 24, Ipv6RowSize = 56;

    public RemoteAccessSnapshot Capture()
    {
        var warnings = new List<string>();
        var names = ProcessNames();
        var endpoints = ReadTcp(AfInet, names, warnings).Concat(ReadTcp(AfInet6, names, warnings)).ToArray();
        var exposures = RemoteAccessAnalyzer.Exposures(endpoints).Take(MaximumRows).ToArray();
        var tools = RemoteAccessAnalyzer.Tools(names.Select(pair => (pair.Key, pair.Value))).Take(MaximumRows).ToArray();
        var (rdpEnabled, nla, port) = ReadRdp();
        var findings = RemoteAccessAnalyzer.Findings(rdpEnabled, nla, exposures, tools);
        return new RemoteAccessSnapshot(1, DateTimeOffset.UtcNow, rdpEnabled, nla, port, exposures, tools, findings, warnings);
    }

    private static Dictionary<int, string> ProcessNames()
    {
        var names = new Dictionary<int, string>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { names[process.Id] = process.ProcessName + ".exe"; }
                catch (InvalidOperationException) { }
            }
        }
        return names;
    }

    private static IEnumerable<TcpEndpoint> ReadTcp(int family, IReadOnlyDictionary<int, string> names, List<string> warnings)
    {
        var size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TcpTableOwnerPidAll, 0);
        if (size <= 0 || size > 16 * 1024 * 1024) return [];
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var result = GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0);
            if (result != 0)
            {
                warnings.Add($"TCP table ({(family == AfInet ? "IPv4" : "IPv6")}) could not be read (error {result}).");
                return [];
            }
            var count = Marshal.ReadInt32(buffer);
            var rowSize = family == AfInet ? Ipv4RowSize : Ipv6RowSize;
            var rows = new List<TcpEndpoint>();
            for (var index = 0; index < count && rows.Count < 8192; index++)
            {
                var row = buffer + 4 + index * rowSize;
                if (4 + (index + 1) * rowSize > size) break;
                int state, localPort, remotePort, pid;
                IPAddress remote;
                if (family == AfInet)
                {
                    state = Marshal.ReadInt32(row);
                    localPort = Port(Marshal.ReadInt32(row, 8));
                    remote = new IPAddress((uint)Marshal.ReadInt32(row, 12));
                    remotePort = Port(Marshal.ReadInt32(row, 16));
                    pid = Marshal.ReadInt32(row, 20);
                }
                else
                {
                    var remoteBytes = new byte[16];
                    Marshal.Copy(row + 24, remoteBytes, 0, 16);
                    localPort = Port(Marshal.ReadInt32(row, 20));
                    remote = new IPAddress(remoteBytes);
                    remotePort = Port(Marshal.ReadInt32(row, 44));
                    state = Marshal.ReadInt32(row, 48);
                    pid = Marshal.ReadInt32(row, 52);
                }
                if (state is not (StateListen or StateEstablished)) continue;
                rows.Add(new TcpEndpoint(state == StateListen, localPort, remote.ToString(), remotePort, IPAddress.IsLoopback(remote), pid,
                    names.TryGetValue(pid, out var name) ? name : pid == 4 ? "System" : "(unknown)"));
            }
            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Ports are stored in network byte order in the low 16 bits.</summary>
    internal static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    private static (bool? Enabled, bool? Nla, int? Port) ReadRdp()
    {
        try
        {
            using var server = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            using var tcp = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            bool? enabled = server?.GetValue("fDenyTSConnections") is int deny ? deny == 0 : null;
            bool? nla = tcp?.GetValue("UserAuthentication") is int auth ? auth != 0 : null;
            int? port = tcp?.GetValue("PortNumber") is int number ? number : null;
            return (enabled, nla, port);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return (null, null, null);
        }
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, int reserved);
}
