using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Fetches one explicitly selected CVE's public FIRST EPSS estimate; it never bulk-downloads scores.</summary>
public sealed class EpssClient
{
    public const string SourceName = "FIRST Exploit Prediction Scoring System";
    public const string Endpoint = "https://api.first.org/data/v1/epss";
    public const int MaximumPayloadBytes = 64 * 1024;
    private static readonly Regex CvePattern = new("^CVE-\\d{4}-\\d{4,}$", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly HttpClient SharedClient = CreateClient();
    private readonly HttpClient _httpClient;

    public EpssClient(HttpClient? httpClient = null) => _httpClient = httpClient ?? SharedClient;

    public async Task<EpssScore?> FetchAsync(string cveId, CancellationToken cancellationToken = default)
    {
        if (!IsValidCve(cveId)) throw new ArgumentException("A bounded CVE identifier is required.", nameof(cveId));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var uri = new Uri($"{Endpoint}?cve={Uri.EscapeDataString(cveId.ToUpperInvariant())}");
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.ParseAdd("application/json");
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (response.RequestMessage?.RequestUri is not { } finalUri || finalUri.Scheme != Uri.UriSchemeHttps ||
            !finalUri.Host.Equals("api.first.org", StringComparison.OrdinalIgnoreCase) || finalUri.AbsolutePath != "/data/v1/epss")
            throw new InvalidDataException("The EPSS response came from an unexpected source.");
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"FIRST returned HTTP {(int)response.StatusCode}.");
        if (response.Content.Headers.ContentLength is > MaximumPayloadBytes)
            throw new InvalidDataException("The EPSS response exceeds the configured size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bounded = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0) break;
            if (bounded.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("The EPSS response exceeds the configured size limit.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
        }

        return Parse(bounded.ToArray(), cveId, DateTimeOffset.UtcNow);
    }

    public static EpssScore? Parse(ReadOnlyMemory<byte> payload, string requestedCve, DateTimeOffset retrievedAtUtc)
    {
        if (!IsValidCve(requestedCve)) throw new ArgumentException("A bounded CVE identifier is required.", nameof(requestedCve));
        if (payload.Length is 0 or > MaximumPayloadBytes)
            throw new InvalidDataException("The EPSS payload is empty or exceeds the configured size limit.");

        JObject root;
        try
        {
            root = BoundedJson.Deserialize<JObject>(payload)
                ?? throw new InvalidDataException("The EPSS response must be a JSON object.");
        }
        catch (JsonReaderException) { throw; }
        catch (JsonSerializationException) { throw; }

        if (!String(root, "status", 16).Equals("OK", StringComparison.Ordinal) ||
            Integer(root, "status-code") != 200 ||
            root.GetValue("data", StringComparison.OrdinalIgnoreCase) is not JArray rows || rows.Count > 1 ||
            Integer(root, "total") != rows.Count)
            throw new InvalidDataException("The EPSS response envelope is invalid.");
        if (rows.Count == 0) return null;
        if (rows[0] is not JObject item) throw new InvalidDataException("The EPSS score record is invalid.");

        var cve = String(item, "cve", 32).ToUpperInvariant();
        if (!cve.Equals(requestedCve, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The EPSS response CVE did not match the requested identifier.");
        var score = Decimal(item, "epss");
        var percentile = Decimal(item, "percentile");
        var dateText = String(item, "date", 10);
        if (score is < 0 or > 1 || percentile is < 0 or > 1 ||
            !DateOnly.TryParseExact(dateText, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ||
            date > DateOnly.FromDateTime(retrievedAtUtc.UtcDateTime.AddDays(1)))
            throw new InvalidDataException("The EPSS score, percentile, or publication date is outside its valid range.");

        return new EpssScore(cve, score, percentile, date, retrievedAtUtc.ToUniversalTime());
    }

    private static bool IsValidCve(string? cve) => cve is { Length: >= 13 and <= 32 } && CvePattern.IsMatch(cve);

    private static HttpClient CreateClient()
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private static string String(JObject obj, string name, int maxLength)
    {
        var value = obj.GetValue(name, StringComparison.OrdinalIgnoreCase);
        if (value?.Type != JTokenType.String) throw new InvalidDataException($"The EPSS response is missing {name}.");
        var text = value.Value<string>()?.Trim();
        if (string.IsNullOrWhiteSpace(text) || text.Length > maxLength || text.Any(char.IsControl))
            throw new InvalidDataException($"The EPSS field {name} is invalid.");
        return text;
    }

    private static int Integer(JObject obj, string name)
    {
        var value = obj.GetValue(name, StringComparison.OrdinalIgnoreCase);
        if (value?.Type != JTokenType.Integer || !int.TryParse(value.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out var result))
            throw new InvalidDataException($"The EPSS field {name} is invalid.");
        return result;
    }

    private static decimal Decimal(JObject obj, string name)
    {
        var value = obj.GetValue(name, StringComparison.OrdinalIgnoreCase);
        if (value?.Type != JTokenType.String ||
            !decimal.TryParse(value.Value<string>(), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var result))
            throw new InvalidDataException($"The EPSS field {name} is invalid.");
        return result;
    }
}

public sealed record EpssScore(string CveId, decimal Score, decimal Percentile, DateOnly ScoreDate, DateTimeOffset RetrievedAtUtc);
