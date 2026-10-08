using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Immutable in-memory index over every loaded feed. Built off the UI thread; lookups are lock-free reads.
/// IPs, domains and hashes share one dictionary (their normalized forms cannot collide); networks are checked by range.
/// </summary>
public sealed class ThreatIndex
{
    private readonly Dictionary<string, int> _first;
    private readonly List<Entry> _entries;
    private readonly List<(IPNetwork Network, int Feed, string Label)> _networks;
    private readonly Dictionary<string, ThreatLolbin> _lolbins;

    private readonly record struct Entry(int Feed, string Label, int Next);

    public static readonly ThreatIndex Empty = Build([]);

    private ThreatIndex(Dictionary<string, int> first, List<Entry> entries, List<(IPNetwork, int, string)> networks, Dictionary<string, ThreatLolbin> lolbins)
    {
        _first = first;
        _entries = entries;
        _networks = networks;
        _lolbins = lolbins;
    }

    public int IndicatorCount => _first.Count + _networks.Count;
    public int LolbinCount => _lolbins.Count;

    public static ThreatIndex Build(IReadOnlyList<(ThreatFeedDefinition Feed, ParsedThreatFeed Parsed)> feeds)
    {
        var first = new Dictionary<string, int>(StringComparer.Ordinal);
        var entries = new List<Entry>();
        var networks = new List<(IPNetwork, int, string)>();
        var lolbins = new Dictionary<string, ThreatLolbin>(StringComparer.OrdinalIgnoreCase);
        foreach (var (feed, parsed) in feeds)
        {
            var feedIndex = IndexOf(feed.Id);
            if (feedIndex < 0) continue;
            foreach (var indicator in parsed.Indicators)
            {
                if (indicator.Type == IndicatorType.Network)
                {
                    if (IPNetwork.TryParse(indicator.Value, out var network)) networks.Add((network, feedIndex, indicator.Label));
                    continue;
                }
                if (indicator.Type == IndicatorType.Ip && IPAddress.TryParse(indicator.Value, out var address) && ThreatFeedParser.IsReserved(address)) continue;
                var head = first.TryGetValue(indicator.Value, out var existing) ? existing : -1;
                // One hit per feed per indicator is enough; feeds often repeat an IP for several ports.
                var duplicate = false;
                for (var i = head; i >= 0; i = entries[i].Next)
                    if (entries[i].Feed == feedIndex) { duplicate = true; break; }
                if (duplicate) continue;
                entries.Add(new Entry(feedIndex, indicator.Label, head));
                first[indicator.Value] = entries.Count - 1;
            }
            foreach (var lolbin in parsed.Lolbins) lolbins[lolbin.Name] = lolbin;
        }
        return new ThreatIndex(first, entries, networks, lolbins);
    }

    private static int IndexOf(string id)
    {
        for (var i = 0; i < ThreatFeedCatalog.All.Count; i++)
            if (ThreatFeedCatalog.All[i].Id == id) return i;
        return -1;
    }

    /// <summary>All feeds listing this indicator. Domains also match listed parent domains (a.evil.example matches evil.example).</summary>
    public IReadOnlyList<(ThreatFeedDefinition Feed, string Label)> Lookup(ThreatIndicator indicator)
    {
        var hits = new List<(ThreatFeedDefinition, string)>();
        switch (indicator.Type)
        {
            case IndicatorType.Ip:
                if (!IPAddress.TryParse(indicator.Value, out var address)) break;
                if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
                if (ThreatFeedParser.IsReserved(address)) break;
                Collect(address.ToString(), hits);
                foreach (var (network, feed, label) in _networks)
                    if (network.BaseAddress.AddressFamily == address.AddressFamily && network.Contains(address) && hits.All(h => h.Item1.Id != ThreatFeedCatalog.All[feed].Id))
                        hits.Add((ThreatFeedCatalog.All[feed], label));
                break;
            case IndicatorType.Domain:
                for (var current = indicator.Value; ; )
                {
                    Collect(current, hits);
                    var dot = current.IndexOf('.');
                    if (dot < 0 || current.IndexOf('.', dot + 1) < 0) break;
                    current = current[(dot + 1)..];
                }
                break;
            case IndicatorType.Sha256 or IndicatorType.Sha1 or IndicatorType.Md5:
                Collect(indicator.Value, hits);
                break;
        }
        return hits;
    }

    /// <summary>Feeds listing exactly this value (no parent-domain or network expansion).</summary>
    public IReadOnlyList<(ThreatFeedDefinition Feed, string Label)> LookupExact(string value)
    {
        var hits = new List<(ThreatFeedDefinition, string)>();
        Collect(value, hits);
        return hits;
    }

    public ThreatLolbin? Lolbin(string fileName) => _lolbins.GetValueOrDefault(fileName);

    private void Collect(string key, List<(ThreatFeedDefinition, string)> hits)
    {
        if (!_first.TryGetValue(key, out var index)) return;
        for (var i = index; i >= 0; i = _entries[i].Next)
            hits.Add((ThreatFeedCatalog.All[_entries[i].Feed], _entries[i].Label));
    }
}

/// <summary>Atomic per-feed cache of payloads that already passed their parser. The digest detects corruption, not tampering.</summary>
public sealed class ThreatFeedCache(string directory)
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("DPTDB001");
    private const int HeaderLength = 8 + sizeof(long) + sizeof(int) + 32;
    public static readonly TimeSpan MaximumAge = TimeSpan.FromDays(30);

    public static ThreatFeedCache CreateForCurrentUser() => new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "threat-db"));

    public string PathFor(ThreatFeedDefinition feed) => Path.Combine(directory, feed.Id + ".v1.cache");

    public (byte[] Payload, DateTimeOffset RetrievedAtUtc)? TryRead(ThreatFeedDefinition feed, DateTimeOffset nowUtc)
    {
        var path = PathFor(feed);
        var info = new FileInfo(path);
        if (!info.Exists) return null;
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length < HeaderLength || info.Length > feed.MaximumBytes + HeaderLength)
            throw new InvalidDataException("The cached feed size is invalid.");
        var bytes = File.ReadAllBytes(path);
        if (!bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic)) throw new InvalidDataException("The cached feed header is invalid.");
        var retrieved = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(8));
        var length = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16));
        if (length <= 0 || bytes.Length != HeaderLength + length) throw new InvalidDataException("The cached feed length is invalid.");
        DateTimeOffset retrievedAt;
        try { retrievedAt = DateTimeOffset.FromUnixTimeSeconds(retrieved); }
        catch (ArgumentOutOfRangeException ex) { throw new InvalidDataException("The cached feed timestamp is invalid.", ex); }
        if (retrievedAt > nowUtc.AddMinutes(5)) throw new InvalidDataException("The cached feed is dated in the future.");
        if (nowUtc - retrievedAt > MaximumAge) return null;
        var payload = bytes.AsSpan(HeaderLength).ToArray();
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), bytes.AsSpan(20, 32)))
            throw new InvalidDataException("The cached feed failed its integrity check.");
        return (payload, retrievedAt);
    }

    public void Write(ThreatFeedDefinition feed, byte[] payload, DateTimeOffset retrievedAtUtc)
    {
        if (payload.Length is 0 || payload.Length > feed.MaximumBytes) throw new InvalidDataException("The feed payload size is invalid.");
        _ = ThreatFeedParser.Parse(feed, payload); // only validated data is ever stored
        Directory.CreateDirectory(directory);
        var path = PathFor(feed);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                var header = new byte[HeaderLength];
                Magic.CopyTo(header, 0);
                BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(8), retrievedAtUtc.ToUnixTimeSeconds());
                BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(16), payload.Length);
                SHA256.HashData(payload, header.AsSpan(20, 32));
                stream.Write(header);
                stream.Write(payload);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}

/// <summary>Downloads one catalogued feed over HTTPS from its fixed host. Redirects are refused and size is enforced while streaming.</summary>
public sealed class ThreatFeedDownloader
{
    private static readonly HttpClient SharedClient = CreateClient();
    private readonly HttpClient _client;
    private readonly TimeSpan _stallTimeout;
    private readonly TimeSpan _overallTimeout;

    public static readonly TimeSpan DefaultStallTimeout = TimeSpan.FromSeconds(45);
    public static readonly TimeSpan DefaultOverallTimeout = TimeSpan.FromMinutes(15);

    public ThreatFeedDownloader(HttpClient? client = null, TimeSpan? stallTimeout = null, TimeSpan? overallTimeout = null)
    {
        _client = client ?? SharedClient;
        _stallTimeout = stallTimeout ?? DefaultStallTimeout;
        _overallTimeout = overallTimeout ?? DefaultOverallTimeout;
    }

    private static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            ConnectTimeout = TimeSpan.FromSeconds(20),
            UseCookies = false,
        };
        var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("DownpourNext/1.0 (+https://github.com/christiand0797/downpour-next)");
        return client;
    }

    public async Task<byte[]> FetchAsync(ThreatFeedDefinition feed, CancellationToken cancellationToken)
    {
        var uri = new Uri(feed.Url);
        if (uri.Scheme != Uri.UriSchemeHttps || ThreatFeedCatalog.Find(feed.Id)?.Url != feed.Url) throw new InvalidOperationException("Only catalogued HTTPS feeds may be downloaded.");
        // Slow links must work: the download fails only when no data arrives for StallTimeout, within an overall cap.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_overallTimeout);
        using var stall = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        stall.CancelAfter(_stallTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, stall.Token).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400) throw new HttpRequestException($"The source redirected ({(int)response.StatusCode}); redirects are not followed.");
        if (!response.IsSuccessStatusCode) throw new HttpRequestException($"The source answered HTTP {(int)response.StatusCode}.");
        if (response.RequestMessage?.RequestUri is { } final && !string.Equals(final.Host, uri.Host, StringComparison.OrdinalIgnoreCase))
            throw new HttpRequestException("The response came from an unexpected host.");
        if (response.Content.Headers.ContentLength > feed.MaximumBytes) throw new InvalidDataException("The feed exceeds its size limit.");
        await using var stream = await response.Content.ReadAsStreamAsync(stall.Token).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while (true)
        {
            stall.CancelAfter(_stallTimeout);
            read = await stream.ReadAsync(chunk, stall.Token).ConfigureAwait(false);
            if (read <= 0) break;
            if (buffer.Length + read > feed.MaximumBytes) throw new InvalidDataException("The feed exceeds its size limit.");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }
}
