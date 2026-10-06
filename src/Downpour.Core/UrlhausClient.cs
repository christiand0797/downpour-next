using System.Net;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Fetches malware URL data from URLhaus API.</summary>
public sealed class UrlhausClient
{
    public const string SourceName = "URLhaus";
    public const string SourceUrl = "https://urlhaus-api.abuse.ch/v1/";
    public const int MaximumPayloadBytes = 10 * 1024 * 1024;
    private static readonly HttpClient SharedClient = CreateClient();
    private readonly HttpClient _httpClient;

    public UrlhausClient(HttpClient? httpClient = null) => _httpClient = httpClient ?? SharedClient;

    public async Task<UrlhausPayload?> FetchRecentUrlsAsync(int limit = 1000, CancellationToken cancellationToken = default)
    {
        if (limit < 1 || limit > 10000) limit = 1000;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var url = $"{SourceUrl}urls/recent/limit/{limit}/";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"URLhaus returned HTTP {(int)response.StatusCode}.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("URLhaus response exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("URLhaus response exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payload = bounded.ToArray();
        return Parse(payload);
    }

    public async Task<UrlhausPayload?> FetchPayloadByTagAsync(string tag, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tag))
            throw new ArgumentException("Tag is required.", nameof(tag));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var url = $"{SourceUrl}tag/{Uri.EscapeDataString(tag)}/";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"URLhaus returned HTTP {(int)response.StatusCode} for tag '{tag}'.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("URLhaus response exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("URLhaus response exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payload = bounded.ToArray();
        return Parse(payload);
    }

    public async Task<UrlhausPayload?> FetchUrlInfoAsync(string url, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("URL is required.", nameof(url));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        var payload = new Dictionary<string, string> { ["url"] = url };

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{SourceUrl}url/")
        {
            Content = new FormUrlEncodedContent(payload)
        };
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"URLhaus returned HTTP {(int)response.StatusCode} for URL lookup.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("URLhaus response exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("URLhaus response exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payloadBytes = bounded.ToArray();
        return Parse(payloadBytes);
    }

    public static UrlhausPayload? Parse(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length is 0 or > MaximumPayloadBytes)
            throw new InvalidDataException("URLhaus payload is empty or exceeds size limit.");

        JObject root;
        try
        {
            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var text = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
            using var reader = new JsonTextReader(text) { MaxDepth = 32, DateParseHandling = DateParseHandling.None, SupportMultipleContent = false };
            root = BoundedJson.ParseStrict(reader) as JObject
                ?? throw new InvalidDataException("URLhaus response root must be a JSON object.");
            if (reader.Read()) throw new JsonReaderException("Unexpected trailing JSON content.");
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("URLhaus response is not valid UTF-8.", exception);
        }

        var queryStatus = root.GetValue("query_status", StringComparison.OrdinalIgnoreCase)?.Value<string>();
        if (queryStatus != "ok")
            return null;

        var urls = new List<UrlhausEntry>();

        if (root.GetValue("urls", StringComparison.OrdinalIgnoreCase) is JArray urlsArray)
        {
            foreach (var item in urlsArray)
            {
                if (item is not JObject urlObj) continue;

                var id = urlObj.GetValue("id", StringComparison.OrdinalIgnoreCase)?.Value<string>();
                var dateAdded = ParseDateTime(urlObj.GetValue("date_added", StringComparison.OrdinalIgnoreCase)?.Value<string>());
                var url = urlObj.GetValue("url", StringComparison.OrdinalIgnoreCase)?.Value<string>();
                var urlStatus = urlObj.GetValue("url_status", StringComparison.OrdinalIgnoreCase)?.Value<string>();
                var threat = urlObj.GetValue("threat", StringComparison.OrdinalIgnoreCase)?.Value<string>();
                var tags = urlObj.GetValue("tags", StringComparison.OrdinalIgnoreCase) as JArray;
                var tagList = tags?.Select(t => t.Value<string>() ?? "").Where(t => !string.IsNullOrEmpty(t)).ToList() ?? new List<string>();
                var reporter = urlObj.GetValue("reporter", StringComparison.OrdinalIgnoreCase)?.Value<string>();
                var urlhausReference = urlObj.GetValue("urlhaus_reference", StringComparison.OrdinalIgnoreCase)?.Value<string>();

                var payloads = new List<UrlhausPayloadInfo>();
                if (urlObj.GetValue("payloads", StringComparison.OrdinalIgnoreCase) is JArray payloadsArray)
                {
                    foreach (var p in payloadsArray)
                    {
                        if (p is not JObject pObj) continue;
                        payloads.Add(new UrlhausPayloadInfo(
                            pObj.GetValue("sha256", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "",
                            pObj.GetValue("sha1", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "",
                            pObj.GetValue("md5", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "",
                            pObj.GetValue("file_type", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "",
                            pObj.GetValue("file_name", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? "",
                            pObj.GetValue("signature", StringComparison.OrdinalIgnoreCase)?.Value<string>() ?? ""));
                    }
                }

                if (!string.IsNullOrEmpty(url))
                {
                    urls.Add(new UrlhausEntry(
                        id ?? "",
                        dateAdded,
                        url,
                        urlStatus ?? "",
                        threat ?? "",
                        tagList,
                        reporter ?? "",
                        urlhausReference ?? "",
                        payloads));
                }
            }
        }

        return new UrlhausPayload(DateTimeOffset.UtcNow, urls);
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

public sealed record UrlhausPayload(DateTimeOffset RetrievedAtUtc, IReadOnlyList<UrlhausEntry> Urls);

public sealed record UrlhausEntry(
    string Id,
    DateTimeOffset DateAdded,
    string Url,
    string UrlStatus,
    string Threat,
    IReadOnlyList<string> Tags,
    string Reporter,
    string UrlhausReference,
    IReadOnlyList<UrlhausPayloadInfo> Payloads);

public sealed record UrlhausPayloadInfo(
    string Sha256,
    string Sha1,
    string Md5,
    string FileType,
    string FileName,
    string Signature);