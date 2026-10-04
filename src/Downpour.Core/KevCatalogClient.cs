using System.Net;
using System.Text.RegularExpressions;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Downloads the public CISA KEV catalog with strict source, size, and schema bounds.</summary>
public sealed class KevCatalogClient
{
    public const string SourceName = "CISA Known Exploited Vulnerabilities Catalog";
    public const string SourceUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    public const int MaximumPayloadBytes = 12 * 1024 * 1024;
    public const int MaximumEntries = 10_000;
    private static readonly Regex CvePattern = new("^CVE-\\d{4}-\\d{4,}$", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly HttpClient SharedClient = CreateClient();
    private readonly HttpClient _httpClient;

    public KevCatalogClient(HttpClient? httpClient = null) => _httpClient = httpClient ?? SharedClient;

    public async Task<KevCatalogSnapshot> FetchAsync(CancellationToken cancellationToken = default) =>
        (await FetchWithPayloadAsync(cancellationToken).ConfigureAwait(false)).Snapshot;

    public async Task<KevCatalogDownload> FetchWithPayloadAsync(CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var request = new HttpRequestMessage(HttpMethod.Get, SourceUrl);
        request.Headers.Accept.ParseAdd("application/json");
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (response.RequestMessage?.RequestUri is not { } finalUri ||
            finalUri.Scheme != Uri.UriSchemeHttps || !finalUri.Host.Equals("www.cisa.gov", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The KEV response came from an unexpected source.");
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"CISA returned HTTP {(int)response.StatusCode}.");
        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("The KEV catalog exceeds the configured size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("The KEV catalog exceeds the configured size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payload = bounded.ToArray();
        var snapshot = Parse(payload) with { RetrievedAtUtc = DateTimeOffset.UtcNow };
        return new KevCatalogDownload(snapshot, payload);
    }

    public static KevCatalogSnapshot Parse(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length is 0 or > MaximumPayloadBytes)
            throw new InvalidDataException("The KEV payload is empty or exceeds the configured size limit.");

        JObject root;
        try
        {
            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var text = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
            using var reader = new JsonTextReader(text) { MaxDepth = 24, DateParseHandling = DateParseHandling.None, SupportMultipleContent = false };
            root = BoundedJson.ParseStrict(reader) as JObject
                ?? throw new InvalidDataException("The KEV catalog root must be a JSON object.");
            if (reader.Read()) throw new JsonReaderException("Unexpected trailing JSON content.");
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("The KEV catalog is not valid UTF-8.", exception);
        }
        if (root.GetValue("vulnerabilities", StringComparison.OrdinalIgnoreCase) is not JArray vulnerabilities || vulnerabilities.Count > MaximumEntries)
            throw new InvalidDataException("The KEV catalog has an invalid envelope or too many records.");
        if (root.GetValue("count", StringComparison.OrdinalIgnoreCase)?.Value<int?>() != vulnerabilities.Count)
            throw new InvalidDataException("The KEV catalog record count does not match its envelope.");

        var version = RequiredString(root, "catalogVersion", 64);
        var released = RequiredDate(root, "dateReleased");
        var rows = new List<KevEntry>(vulnerabilities.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in vulnerabilities)
        {
            if (item is not JObject record) throw new InvalidDataException("The KEV catalog contains a malformed record.");
            var cveId = RequiredString(record, "cveID", 32).ToUpperInvariant();
            if (!CvePattern.IsMatch(cveId) || !seen.Add(cveId))
                throw new InvalidDataException("The KEV catalog contains an invalid or duplicate CVE identifier.");
            var vendor = RequiredString(record, "vendorProject", 256);
            var product = RequiredString(record, "product", 256);
            var name = RequiredString(record, "vulnerabilityName", 512);
            var dateAdded = RequiredDate(record, "dateAdded");
            var description = OptionalString(record, "shortDescription", 2_000);
            rows.Add(new KevEntry(cveId, vendor, product, name, dateAdded, description));
        }

        return new KevCatalogSnapshot(version, released, DateTimeOffset.MinValue, rows);
    }

    private static HttpClient CreateClient()
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private static string RequiredString(JObject obj, string property, int maxLength)
    {
        var value = obj.GetValue(property, StringComparison.OrdinalIgnoreCase);
        if (value?.Type != JTokenType.String)
            throw new InvalidDataException($"The KEV record is missing {property}.");
        var result = value.Value<string>()?.Trim();
        if (string.IsNullOrWhiteSpace(result) || result.Length > maxLength || result.Any(char.IsControl))
            throw new InvalidDataException($"The KEV field {property} is invalid.");
        return result;
    }

    private static string OptionalString(JObject obj, string property, int maxLength)
    {
        var value = obj.GetValue(property, StringComparison.OrdinalIgnoreCase);
        if (value is null || value.Type == JTokenType.Null) return "";
        if (value.Type != JTokenType.String) throw new InvalidDataException($"The KEV field {property} is invalid.");
        var result = value.Value<string>() ?? "";
        if (result.Length > maxLength || result.Any(ch => char.IsControl(ch) && ch is not '\r' and not '\n' and not '\t'))
            throw new InvalidDataException($"The KEV field {property} exceeds its validation limit.");
        return result;
    }

    private static DateOnly RequiredDate(JObject obj, string property)
    {
        var value = RequiredString(obj, property, 10);
        if (!DateOnly.TryParseExact(value, "yyyy-MM-dd", out var parsed))
            throw new InvalidDataException($"The KEV field {property} is not a valid date.");
        return parsed;
    }
}

public sealed record KevCatalogSnapshot(string CatalogVersion, DateOnly ReleasedOn, DateTimeOffset RetrievedAtUtc, IReadOnlyList<KevEntry> Entries);
public sealed record KevEntry(string CveId, string Vendor, string Product, string VulnerabilityName, DateOnly DateAdded, string Description);
public sealed record KevCatalogDownload(KevCatalogSnapshot Snapshot, byte[] Payload);
