using System.Runtime.InteropServices;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>
/// Read-only Wi-Fi state through the Native Wifi API (wlanapi.dll). Replaces parsing of localized netsh output,
/// which only worked on English Windows. Uses the cached network list; it never triggers a scan, connects, or
/// reads profile keys.
/// </summary>
internal static class WlanNative
{
    private const int ErrorServiceNotActive = 1062;
    private const int StateConnected = 1;
    private const int OpcodeCurrentConnection = 7;
    private const int BssTypeAny = 3;
    private const int InterfaceInfoSize = 532;   // GUID (16) + WCHAR[256] (512) + state (4)
    private const int AvailableNetworkSize = 628;
    private const int BssEntrySize = 360;

    public static (bool Available, string? ConnectedSsid, string? ConnectedBssid) Collect(
        List<WifiNetworkEntry> networks, List<string> warnings, int maximumNetworks)
    {
        var open = WlanOpenHandle(2, IntPtr.Zero, out _, out var client);
        if (open == ErrorServiceNotActive)
        {
            warnings.Add("The WLAN AutoConfig service is not running; Wi-Fi state is unavailable.");
            return (false, null, null);
        }
        if (open != 0)
        {
            warnings.Add($"The Native Wifi API could not be opened (error {open}).");
            return (false, null, null);
        }

        try
        {
            if (WlanEnumInterfaces(client, IntPtr.Zero, out var interfaceList) != 0 || interfaceList == IntPtr.Zero)
            {
                warnings.Add("Wi-Fi interfaces could not be enumerated.");
                return (false, null, null);
            }
            try
            {
                var count = Marshal.ReadInt32(interfaceList);
                if (count <= 0) return (false, null, null);
                string? connectedSsid = null, connectedBssid = null;
                for (var index = 0; index < Math.Min(count, 8); index++)
                {
                    var item = interfaceList + 8 + index * InterfaceInfoSize;
                    var guid = Marshal.PtrToStructure<Guid>(item);
                    var state = Marshal.ReadInt32(item, 16 + 512);
                    if (state == StateConnected && connectedSsid is null)
                        (connectedSsid, connectedBssid) = ReadConnection(client, guid);
                    ReadNetworks(client, guid, connectedBssid, networks, maximumNetworks);
                }
                return (true, connectedSsid, connectedBssid);
            }
            finally
            {
                WlanFreeMemory(interfaceList);
            }
        }
        finally
        {
            WlanCloseHandle(client, IntPtr.Zero);
        }
    }

    private static (string?, string?) ReadConnection(IntPtr client, Guid guid)
    {
        if (WlanQueryInterface(client, ref guid, OpcodeCurrentConnection, IntPtr.Zero, out _, out var data, out _) != 0 || data == IntPtr.Zero)
            return (null, null);
        try
        {
            var attributes = Marshal.PtrToStructure<ConnectionAttributes>(data);
            return (DecodeSsid(attributes.Association.Ssid), FormatMac(attributes.Association.Bssid));
        }
        finally
        {
            WlanFreeMemory(data);
        }
    }

    private static void ReadNetworks(IntPtr client, Guid guid, string? connectedBssid, List<WifiNetworkEntry> networks, int maximum)
    {
        if (WlanGetAvailableNetworkList(client, ref guid, 0, IntPtr.Zero, out var list) != 0 || list == IntPtr.Zero) return;
        try
        {
            var count = Marshal.ReadInt32(list);
            for (var index = 0; index < count && networks.Count < maximum; index++)
            {
                var network = Marshal.PtrToStructure<AvailableNetwork>(list + 8 + index * AvailableNetworkSize);
                var ssid = DecodeSsid(network.Ssid);
                var authentication = MapAuthentication(network.DefaultAuthAlgorithm);
                var cipher = MapCipher(network.DefaultCipherAlgorithm);
                var type = network.BssType == 2 ? "Adhoc" : "Infrastructure";
                // BSS entries filtered by this network's SSID and security flag, so an open and a secured
                // network with the same name (an evil twin) produce separate entries.
                foreach (var bss in ReadBssEntries(client, guid, network.Ssid, network.BssType, network.SecurityEnabled))
                {
                    if (networks.Count >= maximum) break;
                    if (networks.Any(existing => existing.Bssid == bss.Bssid && existing.Ssid == ssid)) continue;
                    networks.Add(new WifiNetworkEntry(ssid, bss.Bssid, bss.Quality, authentication, cipher, bss.Channel, type,
                        connectedBssid is not null && bss.Bssid.Equals(connectedBssid, StringComparison.OrdinalIgnoreCase)));
                }
            }
        }
        finally
        {
            WlanFreeMemory(list);
        }
    }

    private static IEnumerable<(string Bssid, int Quality, int Channel)> ReadBssEntries(IntPtr client, Guid guid, Dot11Ssid ssid, int bssType, bool securityEnabled)
    {
        var results = new List<(string, int, int)>();
        var ssidBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Dot11Ssid>());
        try
        {
            Marshal.StructureToPtr(ssid, ssidBuffer, false);
            if (WlanGetNetworkBssList(client, ref guid, ssidBuffer, bssType, securityEnabled, IntPtr.Zero, out var list) != 0 || list == IntPtr.Zero)
                return results;
            try
            {
                var count = Marshal.ReadInt32(list, 4);
                for (var index = 0; index < Math.Min(count, 64); index++)
                {
                    var entry = Marshal.PtrToStructure<BssEntry>(list + 8 + index * BssEntrySize);
                    results.Add((FormatMac(entry.Bssid), (int)Math.Clamp(entry.LinkQuality, 0u, 100u), ChannelFromFrequency(entry.CenterFrequencyKhz)));
                }
            }
            finally
            {
                WlanFreeMemory(list);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(ssidBuffer);
        }
        return results;
    }

    internal static int ChannelFromFrequency(uint kilohertz)
    {
        var mhz = (int)(kilohertz / 1000);
        return mhz switch
        {
            2484 => 14,
            >= 2412 and <= 2472 => (mhz - 2407) / 5,
            >= 5160 and <= 5885 => (mhz - 5000) / 5,
            >= 5955 and <= 7115 => (mhz - 5950) / 5,
            _ => 0
        };
    }

    /// <summary>DOT11_AUTH_ALGORITHM, using the labels netsh prints so existing posture rules keep working.</summary>
    internal static string MapAuthentication(int algorithm) => algorithm switch
    {
        1 => "Open",
        2 => "Shared",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        5 => "WPA-None",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise 192 Bits",
        9 => "WPA3-Personal",
        10 => "OWE",
        11 => "WPA3-Enterprise",
        _ => $"Unknown ({algorithm})"
    };

    internal static string MapCipher(int algorithm) => algorithm switch
    {
        0 => "None",
        1 or 5 or 0x101 => "WEP",
        2 => "TKIP",
        4 => "CCMP",
        6 => "BIP",
        8 => "GCMP",
        9 => "GCMP-256",
        10 => "CCMP-256",
        _ => $"Unknown ({algorithm})"
    };

    private static string DecodeSsid(Dot11Ssid ssid)
    {
        var length = (int)Math.Min(ssid.Length, 32u);
        if (length == 0) return "(hidden)";
        var text = Encoding.UTF8.GetString(ssid.Bytes, 0, length);
        return new string(text.Select(ch => char.IsControl(ch) ? '?' : ch).ToArray());
    }

    private static string FormatMac(byte[] mac) => string.Join(":", mac.Take(6).Select(b => b.ToString("x2")));

    [StructLayout(LayoutKind.Sequential)]
    private struct Dot11Ssid
    {
        public uint Length;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Bytes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct AvailableNetwork
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProfileName;
        public Dot11Ssid Ssid;
        public int BssType;
        public uint NumberOfBssids;
        [MarshalAs(UnmanagedType.Bool)] public bool NetworkConnectable;
        public uint NotConnectableReason;
        public uint NumberOfPhyTypes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public int[] PhyTypes;
        [MarshalAs(UnmanagedType.Bool)] public bool MorePhyTypes;
        public uint SignalQuality;
        [MarshalAs(UnmanagedType.Bool)] public bool SecurityEnabled;
        public int DefaultAuthAlgorithm;
        public int DefaultCipherAlgorithm;
        public uint Flags;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BssEntry
    {
        public Dot11Ssid Ssid;
        public uint PhyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] Bssid;
        public int BssType;
        public int PhyType;
        public int Rssi;
        public uint LinkQuality;
        public byte InRegulatoryDomain;
        public ushort BeaconPeriod;
        public ulong Timestamp;
        public ulong HostTimestamp;
        public ushort CapabilityInformation;
        public uint CenterFrequencyKhz;
        public uint RateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)] public ushort[] RateSet;
        public uint IeOffset;
        public uint IeSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AssociationAttributes
    {
        public Dot11Ssid Ssid;
        public int BssType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] Bssid;
        public int PhyType;
        public uint PhyIndex;
        public uint SignalQuality;
        public uint RxRate;
        public uint TxRate;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ConnectionAttributes
    {
        public int State;
        public int ConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProfileName;
        public AssociationAttributes Association;
    }

    [DllImport("wlanapi.dll")]
    private static extern int WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);

    [DllImport("wlanapi.dll")]
    private static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern int WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll")]
    private static extern int WlanQueryInterface(IntPtr clientHandle, ref Guid interfaceGuid, int opCode, IntPtr reserved,
        out uint dataSize, out IntPtr data, out int opcodeValueType);

    [DllImport("wlanapi.dll")]
    private static extern int WlanGetAvailableNetworkList(IntPtr clientHandle, ref Guid interfaceGuid, uint flags, IntPtr reserved, out IntPtr networkList);

    [DllImport("wlanapi.dll")]
    private static extern int WlanGetNetworkBssList(IntPtr clientHandle, ref Guid interfaceGuid, IntPtr dot11Ssid, int bssType,
        [MarshalAs(UnmanagedType.Bool)] bool securityEnabled, IntPtr reserved, out IntPtr bssList);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);

    /// <summary>Layout guards: these sizes are fixed by wlanapi.h.</summary>
    internal static (int AvailableNetwork, int BssEntry) StructSizes() => (Marshal.SizeOf<AvailableNetwork>(), Marshal.SizeOf<BssEntry>());
}
