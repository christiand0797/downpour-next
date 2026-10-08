using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Offline IP-to-network lookup built from the public-domain IPtoASN dataset (iptoasn.com). Each routed address block maps
/// to the country it is registered in and the autonomous system (ISP, host or VPN provider) announcing it. Lookups never
/// leave the PC, so checking who is connected cannot alert the other side. Results describe a network, not a person.
/// </summary>
public sealed class IpOriginDatabase
{
    public const int MaximumDecompressedBytes = 160 * 1024 * 1024;
    public const int MaximumRows = 2_000_000;
    private const int MaximumNetworkName = 80;

    private readonly uint[] _v4Start, _v4End;
    private readonly int[] _v4Info;
    private readonly UInt128[] _v6Start, _v6End;
    private readonly int[] _v6Info;
    private readonly (int Asn, string Country, string Network)[] _info;

    private IpOriginDatabase(uint[] v4Start, uint[] v4End, int[] v4Info, UInt128[] v6Start, UInt128[] v6End, int[] v6Info, (int, string, string)[] info)
    {
        (_v4Start, _v4End, _v4Info, _v6Start, _v6End, _v6Info, _info) = (v4Start, v4End, v4Info, v6Start, v6End, v6Info, info);
    }

    public int Ranges => _v4Start.Length + _v6Start.Length;

    /// <summary>Parses the gzip TSV (start, end, ASN, country, description). Rows must be sorted and non-overlapping.</summary>
    public static IpOriginDatabase Parse(ReadOnlySpan<byte> gzipPayload)
    {
        string text;
        try
        {
            using var gzip = new GZipStream(new MemoryStream(gzipPayload.ToArray(), writable: false), CompressionMode.Decompress);
            using var bounded = new MemoryStream();
            var buffer = new byte[81920];
            int read;
            while ((read = gzip.Read(buffer)) > 0)
            {
                if (bounded.Length + read > MaximumDecompressedBytes) throw new InvalidDataException("The IP origin data expands beyond its size limit.");
                bounded.Write(buffer, 0, read);
            }
            text = new UTF8Encoding(false, true).GetString(bounded.GetBuffer(), 0, (int)bounded.Length);
        }
        catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or IOException)
        {
            throw new InvalidDataException("The IP origin data is not a valid gzip UTF-8 table.", ex);
        }

        var v4Start = new List<uint>(); var v4End = new List<uint>(); var v4Info = new List<int>();
        var v6Start = new List<UInt128>(); var v6End = new List<UInt128>(); var v6Info = new List<int>();
        var info = new List<(int, string, string)>();
        var infoIndex = new Dictionary<(int, string, string), int>();
        int rows = 0, rejected = 0;
        uint lastV4 = 0; UInt128 lastV6 = 0; bool anyV4 = false, anyV6 = false;
        foreach (var raw in text.AsSpan().EnumerateLines())
        {
            if (raw.IsEmpty) continue;
            if (++rows > MaximumRows) throw new InvalidDataException("The IP origin data has too many rows.");
            var line = raw.ToString();
            var f = line.Split('\t');
            if (f.Length != 5 || !IPAddress.TryParse(f[0], out var start) || !IPAddress.TryParse(f[1], out var end) ||
                start.AddressFamily != end.AddressFamily || !int.TryParse(f[2], out var asn) || asn < 0)
            {
                rejected++;
                continue;
            }
            if (asn == 0) continue; // "Not routed"
            var country = f[3].Length == 2 && f[3].All(char.IsAsciiLetterUpper) ? f[3] : "";
            var network = Clean(f[4]);
            var key = (asn, country, network);
            if (!infoIndex.TryGetValue(key, out var id)) { id = info.Count; info.Add(key); infoIndex[key] = id; }
            if (start.AddressFamily == AddressFamily.InterNetwork)
            {
                uint s = BinaryPrimitives.ReadUInt32BigEndian(start.GetAddressBytes()), e = BinaryPrimitives.ReadUInt32BigEndian(end.GetAddressBytes());
                if (e < s || (anyV4 && s <= lastV4)) { rejected++; continue; }
                v4Start.Add(s); v4End.Add(e); v4Info.Add(id); lastV4 = e; anyV4 = true;
            }
            else
            {
                UInt128 s = BinaryPrimitives.ReadUInt128BigEndian(start.GetAddressBytes()), e = BinaryPrimitives.ReadUInt128BigEndian(end.GetAddressBytes());
                if (e < s || (anyV6 && s <= lastV6)) { rejected++; continue; }
                v6Start.Add(s); v6End.Add(e); v6Info.Add(id); lastV6 = e; anyV6 = true;
            }
        }
        if (v4Start.Count + v6Start.Count < 1000) throw new InvalidDataException("The IP origin data has too few routed ranges.");
        if (rejected > rows / 20) throw new InvalidDataException($"The IP origin data format looks wrong: {rejected:N0} of {rows:N0} rows were invalid.");
        return new IpOriginDatabase(v4Start.ToArray(), v4End.ToArray(), v4Info.ToArray(), v6Start.ToArray(), v6End.ToArray(), v6Info.ToArray(), info.ToArray());
    }

    public IpOrigin? Lookup(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (ThreatFeedParser.IsReserved(address)) return null;
        int index;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var value = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
            index = Find(_v4Start, value);
            if (index < 0 || value > _v4End[index]) return new IpOrigin(address.ToString(), null, null, null);
            index = _v4Info[index];
        }
        else
        {
            var value = BinaryPrimitives.ReadUInt128BigEndian(address.GetAddressBytes());
            index = Find(_v6Start, value);
            if (index < 0 || value > _v6End[index]) return new IpOrigin(address.ToString(), null, null, null);
            index = _v6Info[index];
        }
        var (asn, country, network) = _info[index];
        return new IpOrigin(address.ToString(), country.Length == 2 ? country : null, asn, network.Length > 0 ? network : null);
    }

    /// <summary>Index of the last range starting at or before value, or -1.</summary>
    private static int Find<T>(T[] starts, T value) where T : IComparable<T>
    {
        int lo = 0, hi = starts.Length - 1, found = -1;
        while (lo <= hi)
        {
            var mid = lo + ((hi - lo) >> 1);
            if (starts[mid].CompareTo(value) <= 0) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return found;
    }

    private static string Clean(string value)
    {
        var cleaned = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return cleaned.Length <= MaximumNetworkName ? cleaned : cleaned[..MaximumNetworkName];
    }

    /// <summary>English country name for display; falls back to the code.</summary>
    public static string CountryName(string? code)
    {
        if (code is not { Length: 2 }) return "Unknown";
        try { return new System.Globalization.RegionInfo(code).EnglishName; }
        catch (ArgumentException) { return code; }
    }
}
