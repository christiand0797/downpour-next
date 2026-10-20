using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Immutable in-memory index over every loaded feed. Built off the UI thread; lookups are lock-free reads.
/// Exact values use sorted rows with full ordinal string comparisons, not lossy fingerprints. Feed/label metadata
/// is shared, and only values present in multiple feeds need provenance links. Networks are checked by range.
/// </summary>
public sealed class ThreatIndex
{
    private readonly Entry[] _entries;
    private readonly int _entryCount;
    private readonly Source[] _sources;
    private readonly Link[] _links;
    private readonly List<(IPNetwork Network, int Feed, string Label)> _networks;
    private readonly Dictionary<string, ThreatLolbin> _lolbins;

    // A row is 16 bytes on x64. Before compaction Source/Order identify the input feed/indicator, preserving
    // the first label encountered. Afterwards Source is ~sourceIndex or a nonnegative provenance-link index.
    private readonly record struct Entry(string Value, int Source, int Order);
    private readonly record struct Source(int Feed, string Label);
    private readonly record struct Link(int Source, int Next);
    private sealed class EntryComparer : IComparer<Entry>
    {
        public static readonly EntryComparer Instance = new();
        public int Compare(Entry x, Entry y)
        {
            var value = StringComparer.Ordinal.Compare(x.Value, y.Value);
            if (value != 0) return value;
            var source = x.Source.CompareTo(y.Source);
            return source != 0 ? source : x.Order.CompareTo(y.Order);
        }
    }

    public static readonly ThreatIndex Empty = Build([]);

    private ThreatIndex(Entry[] entries, int entryCount, Source[] sources, Link[] links,
        List<(IPNetwork, int, string)> networks, Dictionary<string, ThreatLolbin> lolbins)
    {
        _entries = entries;
        _entryCount = entryCount;
        _sources = sources;
        _links = links;
        _networks = networks;
        _lolbins = lolbins;
    }

    public int IndicatorCount => _entryCount + _networks.Count;
    public int LolbinCount => _lolbins.Count;

    public static ThreatIndex Build(IReadOnlyList<(ThreatFeedDefinition Feed, ParsedThreatFeed Parsed)> feeds)
    {
        var capacity = 0;
        foreach (var (feed, parsed) in feeds)
            if (IndexOf(feed.Id) >= 0)
                foreach (var indicator in parsed.Indicators)
                    if (indicator.Type != IndicatorType.Network) capacity = checked(capacity + 1);
        var entries = new Entry[capacity];
        var count = 0;
        var feedIndexes = new int[feeds.Count];
        var networks = new List<(IPNetwork, int, string)>();
        var lolbins = new Dictionary<string, ThreatLolbin>(StringComparer.OrdinalIgnoreCase);
        for (var feedPosition = 0; feedPosition < feeds.Count; feedPosition++)
        {
            var (feed, parsed) = feeds[feedPosition];
            var feedIndex = IndexOf(feed.Id);
            feedIndexes[feedPosition] = feedIndex;
            if (feedIndex < 0) continue;
            for (var indicatorPosition = 0; indicatorPosition < parsed.Indicators.Count; indicatorPosition++)
            {
                var indicator = parsed.Indicators[indicatorPosition];
                if (indicator.Type == IndicatorType.Network)
                {
                    if (IPNetwork.TryParse(indicator.Value, out var network)) networks.Add((network, feedIndex, indicator.Label));
                    continue;
                }
                if (indicator.Type == IndicatorType.Ip && IPAddress.TryParse(indicator.Value, out var address) && ThreatFeedParser.IsReserved(address)) continue;
                entries[count] = new Entry(indicator.Value, feedPosition, indicatorPosition);
                count++;
            }
            // The first list to name a program wins, so LOLBAS keeps its built-in tool description over LOLRMM.
            foreach (var lolbin in parsed.Lolbins) lolbins.TryAdd(lolbin.Name, lolbin);
        }
        // Sort and compact the same array, avoiding a second multi-million-key hash table or sorting buffer.
        Array.Sort(entries, 0, count, EntryComparer.Instance);
        var sourceIds = new Dictionary<Source, int>();
        var sources = new List<Source>();
        var links = new List<Link>();
        var seenFeeds = new int[ThreatFeedCatalog.All.Count];
        var distinct = 0;
        for (var start = 0; start < count;)
        {
            var end = start + 1;
            while (end < count && StringComparer.Ordinal.Equals(entries[start].Value, entries[end].Value)) end++;
            var head = 0;
            var matched = 0;
            for (var i = start; i < end; i++)
            {
                var row = entries[i];
                var feed = feedIndexes[row.Source];
                // One hit per feed per indicator, retaining the first label even if later rows disagree.
                if (seenFeeds[feed] == start + 1) continue;
                seenFeeds[feed] = start + 1;
                var source = new Source(feed, feeds[row.Source].Parsed.Indicators[row.Order].Label);
                if (!sourceIds.TryGetValue(source, out var sourceId))
                {
                    sourceId = sources.Count;
                    sources.Add(source);
                    // Bound the temporary interning table even if every indicator supplies a different label.
                    // Additional labels remain intact in the source array; they simply are not interned.
                    if (sourceIds.Count < 65_536) sourceIds.Add(source, sourceId);
                }
                if (matched == 0) head = ~sourceId;
                else
                {
                    if (matched == 1)
                    {
                        links.Add(new Link(~head, -1));
                        head = links.Count - 1;
                    }
                    links.Add(new Link(sourceId, head));
                    head = links.Count - 1;
                }
                matched++;
            }
            entries[distinct++] = new Entry(entries[start].Value, head, 0);
            start = end;
        }
        // Heavy overlap warrants reclaiming the unused rows. Otherwise clear their references in place to
        // avoid the peak allocation of a second similarly-sized array just to remove a little spare capacity.
        if (distinct < entries.Length * 3L / 4) Array.Resize(ref entries, distinct);
        else Array.Clear(entries, distinct, entries.Length - distinct);
        return new ThreatIndex(entries, distinct, sources.ToArray(), links.ToArray(), networks, lolbins);
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
        var lower = 0;
        var upper = _entryCount - 1;
        while (lower <= upper)
        {
            var middle = lower + ((upper - lower) >> 1);
            var comparison = StringComparer.Ordinal.Compare(_entries[middle].Value, key);
            if (comparison < 0) lower = middle + 1;
            else if (comparison > 0) upper = middle - 1;
            else
            {
                var head = _entries[middle].Source;
                if (head < 0) AddSource(~head, hits);
                else
                    for (var i = head; i >= 0; i = _links[i].Next) AddSource(_links[i].Source, hits);
                return;
            }
        }
    }

    private void AddSource(int sourceIndex, List<(ThreatFeedDefinition, string)> hits)
    {
        var source = _sources[sourceIndex];
        hits.Add((ThreatFeedCatalog.All[source.Feed], source.Label));
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

    public string PathFor(ThreatFeedDefinition feed)
    {
        if (feed.CacheGeneration is < 1 or > 1000) throw new InvalidDataException("Invalid feed cache generation.");
        // A changed dataset under the same source ID must not reuse the previous subset's payload.
        // Generation is independent of the cache file format; unchanged feeds retain their existing files.
        var generation = feed.CacheGeneration == 1 ? "" : $".g{feed.CacheGeneration}";
        return Path.Combine(directory, feed.Id + generation + ".v1.cache");
    }

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
