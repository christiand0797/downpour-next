using System.Net;
using System.Text.RegularExpressions;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Fetches CVE data from NVD API with CPE 2.3 matching support.</summary>
public sealed class NvdClient
{
    public const string SourceName = "NVD National Vulnerability Database";
    public const string SourceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    public const int MaximumPayloadBytes = 20 * 1024 * 1024;
    public const int MaximumEntries = 5000;
    private static readonly Regex CvePattern = new("^CVE-\\d{4}-\\d{4,}$", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly HttpClient SharedClient = CreateClient();
    private readonly HttpClient _httpClient;

    public NvdClient(HttpClient? httpClient = null) => _httpClient = httpClient ?? SharedClient;

    public async Task<NvdCatalogSnapshot?> FetchCveAsync(string cveId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(cveId) || !CvePattern.IsMatch(cveId))
            throw new ArgumentException("Invalid CVE identifier format.", nameof(cveId));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        var url = $"{SourceUrl}?cveId={Uri.EscapeDataString(cveId)}";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"NVD returned HTTP {(int)response.StatusCode} for {cveId}.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException($"NVD response for {cveId} exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException($"NVD response for {cveId} exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payload = bounded.ToArray();
        return Parse(payload, cveId);
    }

    public async Task<NvdCatalogSnapshot?> FetchCvesAsync(string keyword, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyword))
            throw new ArgumentException("Keyword is required.", nameof(keyword));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var url = $"{SourceUrl}?keywordSearch={Uri.EscapeDataString(keyword)}&resultsPerPage={Math.Min(MaximumEntries, 2000)}";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("Downpour-Next/1.0 (+https://github.com/christiand0797/downpour-next)");

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"NVD returned HTTP {(int)response.StatusCode} for keyword '{keyword}'.");

        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException($"NVD response for keyword '{keyword}' exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException($"NVD response for keyword '{keyword}' exceeds size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        var payload = bounded.ToArray();
        return Parse(payload);
    }

    public static NvdCatalogSnapshot? Parse(ReadOnlyMemory<byte> payload, string? singleCveId = null)
    {
        if (payload.Length is 0 or > MaximumPayloadBytes)
            throw new InvalidDataException("NVD payload is empty or exceeds size limit.");

        JObject root;
        try
        {
            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var text = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
            using var reader = new JsonTextReader(text) { MaxDepth = 48, DateParseHandling = DateParseHandling.None, SupportMultipleContent = false };
            root = BoundedJson.ParseStrict(reader) as JObject
                ?? throw new InvalidDataException("NVD response root must be a JSON object.");
            if (reader.Read()) throw new JsonReaderException("Unexpected trailing JSON content.");
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("NVD response is not valid UTF-8.", exception);
        }

        if (root.GetValue("vulnerabilities", StringComparison.OrdinalIgnoreCase) is not JArray vulnerabilities || vulnerabilities.Count > MaximumEntries)
            throw new InvalidDataException("NVD response has invalid envelope or too many records.");

        var totalResults = root.GetValue("totalResults", StringComparison.OrdinalIgnoreCase)?.Value<int?>() ?? vulnerabilities.Count;
        var format = RequiredString(root, "format", 32);
        var version = RequiredString(root, "version", 16);
        var timestamp = RequiredDateTimeOffset(root, "timestamp");

        var rows = new List<NvdCveEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in vulnerabilities)
        {
            if (item is not JObject vuln) continue;

            if (vuln.GetValue("cve", StringComparison.OrdinalIgnoreCase) is not JObject cveObj) continue;

            var cveId = RequiredString(cveObj, "id", 32).ToUpperInvariant();
            if (!CvePattern.IsMatch(cveId) || !seen.Add(cveId))
                continue;

            var published = RequiredDateTimeOffset(cveObj, "published");
            var lastModified = RequiredDateTimeOffset(cveObj, "lastModified");
            var vulnStatus = RequiredString(cveObj, "vulnStatus", 64);

            string? description = null;
            if (cveObj.GetValue("descriptions", StringComparison.OrdinalIgnoreCase) is JArray descriptions)
            {
                foreach (var desc in descriptions)
                {
                    if (desc is JObject descObj &&
                        descObj.GetValue("lang", StringComparison.OrdinalIgnoreCase)?.Value<string>() == "en" &&
                        descObj.GetValue("value", StringComparison.OrdinalIgnoreCase) is JToken valToken)
                    {
                        description = valToken.Value<string>() ?? "";
                        break;
                    }
                }
            }

            var metrics = cveObj.GetValue("metrics", StringComparison.OrdinalIgnoreCase) as JObject;
            var cvssV31 = metrics?.GetValue("cvssMetricV31", StringComparison.OrdinalIgnoreCase) as JArray;
            var cvssV30 = metrics?.GetValue("cvssMetricV30", StringComparison.OrdinalIgnoreCase) as JArray;
            var cvssV20 = metrics?.GetValue("cvssMetricV2", StringComparison.OrdinalIgnoreCase) as JArray;

            var cvssScore = ParseCvssScore(cvssV31 ?? cvssV30);
            var cvssVector = ParseCvssVector(cvssV31 ?? cvssV30);
            var cvssV2Score = ParseCvssScore(cvssV20);
            var cvssV2Vector = ParseCvssVector(cvssV20);

            var cpeMatches = new List<NvdCpeMatch>();
            if (cveObj.GetValue("configurations", StringComparison.OrdinalIgnoreCase) is JArray configurations)
            {
                foreach (var config in configurations)
                {
                    if (config is not JObject configObj) continue;
                    if (configObj.GetValue("nodes", StringComparison.OrdinalIgnoreCase) is JArray nodes)
                    {
                        foreach (var node in nodes)
                        {
                            if (node is not JObject nodeObj) continue;
                            if (nodeObj.GetValue("cpeMatch", StringComparison.OrdinalIgnoreCase) is JArray nodeCpeMatches)
                            {
                                foreach (var match in nodeCpeMatches)
                                {
                                    if (match is JObject matchObj &&
                                        matchObj.GetValue("vulnerable", StringComparison.OrdinalIgnoreCase)?.Value<bool>() == true)
                                    {
                                        var cpe23Uri = matchObj.GetValue("criteria", StringComparison.OrdinalIgnoreCase)?.Value<string>();
                                        if (!string.IsNullOrWhiteSpace(cpe23Uri))
                                        {
                                            cpeMatches.Add(ParseCpe23Uri(cpe23Uri));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            var references = new List<string>();
            if (cveObj.GetValue("references", StringComparison.OrdinalIgnoreCase) is JArray refs)
            {
                foreach (var refObj in refs)
                {
                    if (refObj is JObject refObj2 &&
                        refObj2.GetValue("url", StringComparison.OrdinalIgnoreCase)?.Value<string>() is { } url)
                        references.Add(url);
                }
            }

            var cveEntry = new NvdCveEntry(
                cveId,
                published,
                lastModified,
                vulnStatus,
                description ?? "",
                cvssScore,
                cvssVector,
                cvssV2Score,
                cvssV2Vector,
                cpeMatches,
                references);

            rows.Add(cveEntry);
        }

        return new NvdCatalogSnapshot(totalResults, DateTimeOffset.UtcNow, rows);
    }

    private static double? ParseCvssScore(JArray? metrics)
    {
        if (metrics == null || metrics.Count == 0) return null;
        foreach (var metric in metrics)
        {
            if (metric is JObject metricObj)
            {
                var cvssData = metricObj.GetValue("cvssData", StringComparison.OrdinalIgnoreCase) as JObject;
                if (cvssData?.GetValue("baseScore", StringComparison.OrdinalIgnoreCase)?.Value<double>() is double score)
                    return score;
            }
        }
        return null;
    }

    private static string? ParseCvssVector(JArray? metrics)
    {
        if (metrics == null || metrics.Count == 0) return null;
        foreach (var metric in metrics)
        {
            if (metric is JObject metricObj)
            {
                var cvssData = metricObj.GetValue("cvssData", StringComparison.OrdinalIgnoreCase) as JObject;
                if (cvssData?.GetValue("vectorString", StringComparison.OrdinalIgnoreCase)?.Value<string>() is { } vector)
                    return vector;
            }
        }
        return null;
    }

    private static NvdCpeMatch ParseCpe23Uri(string cpe23Uri)
    {
        // CPE 2.3 format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        var parts = cpe23Uri.Split(':');
        if (parts.Length < 6) return new NvdCpeMatch(cpe23Uri, "", "", "", false);

        var part = parts[2]; // 'a' (application), 'o' (os), 'h' (hardware)
        var vendor = parts.Length > 3 ? parts[3] : "";
        var product = parts.Length > 4 ? parts[4] : "";
        var version = parts.Length > 5 ? parts[5] : "";
        var update = parts.Length > 6 ? parts[6] : "";
        var edition = parts.Length > 7 ? parts[7] : "";
        var language = parts.Length > 8 ? parts[8] : "";
        var swEdition = parts.Length > 9 ? parts[9] : "";
        var targetSw = parts.Length > 10 ? parts[10] : "";
        var targetHw = parts.Length > 11 ? parts[11] : "";
        var other = parts.Length > 12 ? parts[12] : "";

        var isVulnerable = true; // We only parse vulnerable matches

        return new NvdCpeMatch(cpe23Uri, vendor, product, version, isVulnerable);
    }

    private static string RequiredString(JObject obj, string property, int maxLength)
    {
        var value = obj.GetValue(property, StringComparison.OrdinalIgnoreCase);
        if (value?.Type != JTokenType.String)
            throw new InvalidDataException($"NVD record missing {property}.");
        var result = value.Value<string>()?.Trim();
        if (string.IsNullOrWhiteSpace(result) || result.Length > maxLength || result.Any(char.IsControl))
            throw new InvalidDataException($"NVD field {property} is invalid.");
        return result;
    }

    private static DateTimeOffset RequiredDateTimeOffset(JObject obj, string property)
    {
        var value = RequiredString(obj, property, 32);
        if (!DateTimeOffset.TryParse(value, out var parsed))
            throw new InvalidDataException($"NVD field {property} is not a valid date-time.");
        return parsed;
    }

    private static HttpClient CreateClient()
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }
}

public sealed record NvdCatalogSnapshot(int TotalResults, DateTimeOffset RetrievedAtUtc, IReadOnlyList<NvdCveEntry> Entries);

public sealed record NvdCveEntry(
    string CveId,
    DateTimeOffset Published,
    DateTimeOffset LastModified,
    string VulnStatus,
    string Description,
    double? CvssV31Score,
    string? CvssV31Vector,
    double? CvssV20Score,
    string? CvssV20Vector,
    IReadOnlyList<NvdCpeMatch> CpeMatches,
    IReadOnlyList<string> References);

public sealed record NvdCpeMatch(
    string Cpe23Uri,
    string Vendor,
    string Product,
    string Version,
    bool IsVulnerable);