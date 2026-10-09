using System.Globalization;
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

    /// <summary>Parses the CISA catalog. Any malformed input surfaces as <see cref="InvalidDataException"/> only.</summary>
    public static KevCatalogSnapshot Parse(ReadOnlyMemory<byte> payload)
    {
        try
        {
            return ParseCore(payload);
        }
        catch (Exception exception) when (exception is JsonException or FormatException or InvalidCastException or OverflowException or ArgumentException)
        {
            throw new InvalidDataException("The KEV catalog is not valid JSON in the expected shape.", exception);
        }
    }

    private static KevCatalogSnapshot ParseCore(ReadOnlyMemory<byte> payload)
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
        if (root.GetValue("count", StringComparison.OrdinalIgnoreCase) is not JValue { Type: JTokenType.Integer } count || count.Value<long>() != vulnerabilities.Count)
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
            var action = Lenient(record, "requiredAction", 1_000);
            var due = OptionalDate(record, "dueDate");
            var ransomware = Lenient(record, "knownRansomwareCampaignUse", 32).Equals("Known", StringComparison.OrdinalIgnoreCase);
            var notes = Lenient(record, "notes", 2_000);
            rows.Add(new KevEntry(cveId, vendor, product, name, dateAdded, description, action, due, ransomware, notes));
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

    /// <summary>Optional display text that is cut to length and stripped of control characters instead of failing the catalog.</summary>
    private static string Lenient(JObject obj, string property, int maxLength)
    {
        if (obj.GetValue(property, StringComparison.OrdinalIgnoreCase) is not JValue { Type: JTokenType.String } value) return "";
        var text = new string((value.Value<string>() ?? "").Where(ch => !char.IsControl(ch)).Take(maxLength).ToArray());
        return text.Trim();
    }

    private static DateOnly? OptionalDate(JObject obj, string property) =>
        obj.GetValue(property, StringComparison.OrdinalIgnoreCase) is JValue { Type: JTokenType.String } value &&
        DateOnly.TryParseExact(value.Value<string>(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date : null;

    private static DateOnly RequiredDate(JObject obj, string property)
    {
        // CISA publishes plain dates ("2026-10-04") and, since late 2026, ISO 8601 UTC timestamps for dateReleased
        // ("2026-10-04T18:52:56.0635Z"). Both are accepted; anything else is still rejected.
        var value = RequiredString(obj, property, 40);
        if (DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            return parsed;
        if (value.Length > 10 && value[10] == 'T' &&
            DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var stamp))
            return DateOnly.FromDateTime(stamp.UtcDateTime);
        throw new InvalidDataException($"The KEV field {property} is not a valid date.");
    }
}

public sealed record KevCatalogSnapshot(string CatalogVersion, DateOnly ReleasedOn, DateTimeOffset RetrievedAtUtc, IReadOnlyList<KevEntry> Entries);
/// <summary>One CISA KEV record. RequiredAction and DueDate are CISA's remediation instruction and federal deadline.</summary>
public sealed record KevEntry(string CveId, string Vendor, string Product, string VulnerabilityName, DateOnly DateAdded, string Description,
    string RequiredAction = "", DateOnly? DueDate = null, bool RansomwareUse = false, string Notes = "");
public sealed record KevCatalogDownload(KevCatalogSnapshot Snapshot, byte[] Payload);
