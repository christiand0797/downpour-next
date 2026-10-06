using System.Net;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Fetches malware data from Abuse.ch APIs (Malware Bazaar, Feodo Tracker, SSL Blacklist).</summary>
public sealed class AbuseChClient
{
    public const string MalwareBazaarUrl = "https://mb-api.abuse.ch/api/v1/";
    public const string FeodoTrackerUrl = "https://feodotracker.abuse.ch/downloads/";
    public const string SslBlacklistUrl = "https://sslbl.abuse.ch/blacklist/";
    public const int MaximumPayloadBytes = 10 * 1024 * 1024;
    private static readonly HttpClient SharedClient = CreateClient();
    private readonly HttpClient _httpClient;

    public AbuseChClient(HttpClient? httpClient = null) => _httpClient = httpClient ?? SharedClient;

    // Malware Bazaar API
    public async Task<MalwareBazaarPayload?> FetchRecentSamplesAsync(int limit = 1000, CancellationToken cancellationToken = default)
    {
        if (limit < 1 || limit > 10000) limit = 1000;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));

        var payload = new Dictionary<string, string>
        {
            ["query"] = "get_recent",
            ["selector"] = "100",
            ["limit"] = limit.ToString()
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, MalwareBazaarUrl)
        {
            Content = new FormUrlEncodedContent(payload)
        };
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"Malware Bazaar returned HTTP {(int)response.StatusCode}.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("Malware Bazaar response exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("Malware Bazaar response exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payloadBytes = bounded.ToArray();
        return ParseMalwareBazaar(payloadBytes);
    }

    public async Task<MalwareBazaarPayload?> FetchSampleInfoAsync(string hash, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hash))
            throw new ArgumentException("Hash is required.", nameof(hash));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));

        var payload = new Dictionary<string, string>
        {
            ["query"] = "get_info",
            ["hash"] = hash
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, MalwareBazaarUrl)
        {
            Content = new FormUrlEncodedContent(payload)
        };
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"Malware Bazaar returned HTTP {(int)response.StatusCode} for hash '{hash}'.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("Malware Bazaar response exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("Malware Bazaar response exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payloadBytes = bounded.ToArray();
        return ParseMalwareBazaar(payloadBytes);
    }

    // Feodo Tracker - IP blocklist for C2 servers
    public async Task<FeodoTrackerPayload?> FetchFeodoIpBlocklistAsync(CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var url = $"{FeodoTrackerUrl}ipblocklist_recommended.json";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"Feodo Tracker returned HTTP {(int)response.StatusCode}.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("Feodo Tracker response exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("Feodo Tracker response exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payloadBytes = bounded.ToArray();
        return ParseFeodoTracker(payloadBytes);
    }

    // SSL Blacklist - JA3 fingerprints for malicious SSL connections
    public async Task<SslBlacklistPayload?> FetchSslBlacklistAsync(CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var url = $"{SslBlacklistUrl}sslblacklist.csv";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("text/csv");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"SSL Blacklist returned HTTP {(int)response.StatusCode}.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("SSL Blacklist response exceeds size limit.");

        var content = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
        return ParseSslBlacklist(content);
    }

    public static MalwareBazaarPayload? ParseMalwareBazaar(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length is 0 or > MaximumPayloadBytes)
            throw new InvalidDataException("Malware Bazaar payload is empty or exceeds size limit.");

        JObject root;
        try
        {
            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var text = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
            using var reader = new JsonTextReader(text) { MaxDepth = 32, DateParseHandling = DateParseHandling.None, SupportMultipleContent = false };
            root = BoundedJson.ParseStrict(reader) as JObject
                ?? throw new InvalidDataException("Malware Bazaar response root must be a JSON object.");
            if (reader.Read()) throw new JsonReaderException("Unexpected trailing JSON content.");
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("Malware Bazaar response is not valid UTF-8.", exception);
        }

        var queryStatus = root.GetValue("query_status", StringComparison.OrdinalIgnoreCase)?.Value<string>();
        if (queryStatus != "ok")
            return null;

        var samples = new List<MalwareBazaarSample>();

        if (root.GetValue("data", StringComparison.OrdinalIgnoreCase) is JArray dataArray)
        {
            foreach (var item in dataArray)
            {
                if (item is not JObject sampleObj) continue;

                var sha256 = sampleObj.GetValue("sha256_hash", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var sha1 = sampleObj.GetValue("sha1_hash", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var md5 = sampleObj.GetValue("md5_hash", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var fileName = sampleObj.GetValue("file_name", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var fileType = sampleObj.GetValue("file_type", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var mimeType = sampleObj.GetValue("mime_type", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var signature = sampleObj.GetValue("signature", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var firstSeen = ParseDateTime(sampleObj.GetValue("first_seen", StringComparison.OrdinalIgnoreCase)?.Value<string>());
                var lastSeen = ParseDateTime(sampleObj.GetValue("last_seen", StringComparison.OrdinalIgnoreCase)?.Value<string>());
                var fileSize = sampleObj.GetValue("file_size", StringComparison.OrdinalIgnoreCase)?.Value<long?>();
                var reporter = sampleObj.GetValue("reporter", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var tags = sampleObj.GetValue("tags", StringComparison.OrdinalIgnoreCase) as JArray;
                var tagList = tags?.Select(t => t.Value<string>() ?? "").Where(t => !string.IsNullOrEmpty(t)).ToList() ?? new List<string>();
                var intelligence = sampleObj.GetValue("intelligence", StringComparison.OrdinalIgnoreCase) as JObject;

                var yaraMatches = new List<string>();
                if (intelligence?.GetValue("yara", StringComparison.OrdinalIgnoreCase) is JArray yaraArray)
                {
                    foreach (var y in yaraArray)
                    {
                        if (y is JObject yObj && yObj.GetValue("rule", StringComparison.OrdinalIgnoreCase)?.Value<string>() is { } rule)
                            yaraMatches.Add(rule);
                    }
                }

                var clamav = intelligence?.GetValue("clamav", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var suricata = intelligence?.GetValue("suricata", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var vtDetection = intelligence?.GetValue("virustotal", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";

                samples.Add(new MalwareBazaarSample(
                    sha256, sha1, md5, fileName, fileType, mimeType, signature,
                    firstSeen, lastSeen, fileSize, reporter, tagList,
                    yaraMatches, clamav, suricata, vtDetection));
            }
        }

        return new MalwareBazaarPayload(DateTimeOffset.UtcNow, samples);
    }

    public static FeodoTrackerPayload? ParseFeodoTracker(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length is 0 or > MaximumPayloadBytes)
            throw new InvalidDataException("Feodo Tracker payload is empty or exceeds size limit.");

        JObject root;
        try
        {
            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var text = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
            using var reader = new JsonTextReader(text) { MaxDepth = 32, DateParseHandling = DateParseHandling.None, SupportMultipleContent = false };
            root = BoundedJson.ParseStrict(reader) as JObject
                ?? throw new InvalidDataException("Feodo Tracker response root must be a JSON object.");
            if (reader.Read()) throw new JsonReaderException("Unexpected trailing JSON content.");
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("Feodo Tracker response is not valid UTF-8.", exception);
        }

        var entries = new List<FeodoTrackerEntry>();

        if (root.GetValue("recommended", StringComparison.OrdinalIgnoreCase) is JArray recArray)
        {
            foreach (var item in recArray)
            {
                if (item is not JObject entryObj) continue;

                var ip = entryObj.GetValue("ip", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var port = entryObj.GetValue("port", StringComparison.OrdinalIgnoreCase)?.Value<int?>();
                var protocol = entryObj.GetValue("protocol", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var malware = entryObj.GetValue("malware", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var firstSeen = ParseDateTime(entryObj.GetValue("first_seen", StringComparison.OrdinalIgnoreCase)?.Value<string>());
                var lastSeen = ParseDateTime(entryObj.GetValue("last_seen", StringComparison.OrdinalIgnoreCase)?.Value<string>());
                var c2Status = entryObj.GetValue("c2_status", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var isp = entryObj.GetValue("isp", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var asn = entryObj.GetValue("asn", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";
                var country = entryObj.GetValue("country", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "";

                if (!string.IsNullOrEmpty(ip))
                {
                    entries.Add(new FeodoTrackerEntry(
                        ip, port, protocol, malware, firstSeen, lastSeen, c2Status, isp, asn, country));
                }
            }
        }

        return new FeodoTrackerPayload(DateTimeOffset.UtcNow, entries);
    }

    public static SslBlacklistPayload? ParseSslBlacklist(string csvContent)
    {
        if (string.IsNullOrWhiteSpace(csvContent))
            throw new InvalidDataException("SSL Blacklist content is empty.");

        var entries = new List<SslBlacklistEntry>();
        var lines = csvContent.Split('\n');

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var parts = line.Split(',');
            if (parts.Length < 7) continue;

            var sha1 = parts[0].Trim().Trim('"');
            var ja3 = parts[1].Trim().Trim('"');
            var ja3s = parts[2].Trim().Trim('"');
            var firstSeen = ParseDateTime(parts[3].Trim().Trim('"'));
            var lastSeen = ParseDateTime(parts[4].Trim().Trim('"'));
            var reason = parts[5].Trim().Trim('"');
            var reference = parts[6].Trim().Trim('"');

            if (!string.IsNullOrEmpty(ja3))
            {
                entries.Add(new SslBlacklistEntry(sha1, ja3, ja3s, firstSeen, lastSeen, reason, reference));
            }
        }

        return new SslBlacklistPayload(DateTimeOffset.UtcNow, entries);
    }

    private static DateTimeOffset ParseDateTime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return DateTimeOffset.MinValue;
        if (DateTimeOffset.TryParse(value, out var parsed)) return parsed;
        return DateTimeOffset.MinValue;
    }

    private static HttpClient CreateClient()
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }
}

public sealed record MalwareBazaarPayload(DateTimeOffset RetrievedAtUtc, IReadOnlyList<MalwareBazaarSample> Samples);

public sealed record MalwareBazaarSample(
    string Sha256,
    string Sha1,
    string Md5,
    string FileName,
    string FileType,
    string MimeType,
    string Signature,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    long? FileSize,
    string Reporter,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> YaraMatches,
    string Clamav,
    string Suricata,
    string Virustotal);

public sealed record FeodoTrackerPayload(DateTimeOffset RetrievedAtUtc, IReadOnlyList<FeodoTrackerEntry> Entries);

public sealed record FeodoTrackerEntry(
    string Ip,
    int? Port,
    string Protocol,
    string Malware,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    string C2Status,
    string Isp,
    string Asn,
    string Country);

public sealed record SslBlacklistPayload(DateTimeOffset RetrievedAtUtc, IReadOnlyList<SslBlacklistEntry> Entries);

public sealed record SslBlacklistEntry(
    string Sha1,
    string Ja3,
    string Ja3s,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    string Reason,
    string Reference);