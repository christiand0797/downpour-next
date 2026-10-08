using System.Net;
using System.Runtime.InteropServices;

namespace Downpour.Service;

/// <summary>
/// Reads the addresses a name already resolved to from the local Windows DNS cache only (DNS_QUERY_NO_WIRE_QUERY), so
/// attributing a listed domain to a connection never sends a DNS request that could tip off or contact the listed server.
/// </summary>
internal static class DnsCacheResolver
{
    private const ushort TypeA = 1;
    private const ushort TypeAaaa = 28;
    private const uint QueryNoWireQuery = 0x10;
    private const int MaximumAddresses = 16;

    public static IReadOnlyList<string> CachedAddresses(string name)
    {
        var addresses = new List<string>();
        if (name.Length is 0 or > 253) return addresses;
        Collect(name, TypeA, addresses);
        Collect(name, TypeAaaa, addresses);
        return addresses;
    }

    private static void Collect(string name, ushort type, List<string> addresses)
    {
        var results = IntPtr.Zero;
        try
        {
            if (DnsQuery_W(name, type, QueryNoWireQuery, IntPtr.Zero, out results, IntPtr.Zero) != 0 || results == IntPtr.Zero) return;
            var dataOffset = IntPtr.Size * 2 + 2 + 2 + 4 + 4 + 4; // pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved
            for (var record = results; record != IntPtr.Zero && addresses.Count < MaximumAddresses; record = Marshal.ReadIntPtr(record))
            {
                var recordType = (ushort)Marshal.ReadInt16(record, IntPtr.Size * 2);
                if (recordType == TypeA)
                {
                    var bytes = BitConverter.GetBytes(Marshal.ReadInt32(record, dataOffset));
                    addresses.Add(new IPAddress(bytes).ToString());
                }
                else if (recordType == TypeAaaa)
                {
                    var bytes = new byte[16];
                    Marshal.Copy(record + dataOffset, bytes, 0, 16);
                    addresses.Add(new IPAddress(bytes).ToString());
                }
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or AccessViolationException) { }
        finally
        {
            if (results != IntPtr.Zero) DnsRecordListFree(results, 1 /* DnsFreeRecordList */);
        }
    }

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
    private static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [DllImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
    private static extern void DnsRecordListFree(IntPtr records, int freeType);
}
