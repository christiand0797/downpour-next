using System.Net;
using Downpour.Contracts;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Request building and response parsing for each supported intel service. No I/O happens here.</summary>
public static class IntelProviders
{
    public static bool Supports(string service, string kind) => service switch
    {
        IntelServices.VirusTotal => IntelKinds.All.Contains(kind),
        IntelServices.AbuseIpDb or IntelServices.GreyNoise => kind == IntelKinds.Ip,
        _ => false
    };

    /// <summary>Fixed HTTPS host for each service; responses from any other host are rejected.</summary>
    public static string Host(string service) => service switch
    {
        IntelServices.VirusTotal => "www.virustotal.com",
        IntelServices.AbuseIpDb => "api.abuseipdb.com",
        IntelServices.GreyNoise => "api.greynoise.io",
        _ => throw new ArgumentOutOfRangeException(nameof(service))
    };

    public static HttpRequestMessage BuildRequest(string service, IntelIndicator indicator, string apiKey)
    {
        if (!Supports(service, indicator.Kind)) throw new ArgumentException("Unsupported service and indicator combination.");
        var value = Uri.EscapeDataString(indicator.Value);
        var uri = service switch
        {
            IntelServices.VirusTotal => indicator.Kind switch
            {
                IntelKinds.Ip => $"https://www.virustotal.com/api/v3/ip_addresses/{value}",
                IntelKinds.Domain => $"https://www.virustotal.com/api/v3/domains/{value}",
                _ => $"https://www.virustotal.com/api/v3/files/{value}",
            },
            IntelServices.AbuseIpDb => $"https://api.abuseipdb.com/api/v2/check?ipAddress={value}&maxAgeInDays=90",
            _ => $"https://api.greynoise.io/v3/community/{value}",
        };
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.TryAddWithoutValidation(service switch
        {
            IntelServices.VirusTotal => "x-apikey",
            IntelServices.AbuseIpDb => "Key",
            _ => "key",
        }, apiKey);
        return request;
    }

    /// <summary>Maps a service response to a result. Unexpected shapes become Unknown rather than a guessed verdict.</summary>
    public static IntelLookupResult Parse(string service, IntelIndicator indicator, HttpStatusCode status, ReadOnlyMemory<byte> body, DateTimeOffset now)
    {
        IntelLookupResult Result(string verdict, int? score, string summary) =>
            new(service, indicator.Kind, indicator.Value, verdict, score, summary.Length <= 256 ? summary : summary[..256], now);

        if (status == HttpStatusCode.NotFound)
            return Result(IntelVerdicts.Unknown, null, service == IntelServices.GreyNoise ? "Not observed by GreyNoise" : "Not found");
        if (status != HttpStatusCode.OK)
            return Result(IntelVerdicts.Unknown, null, $"HTTP {(int)status}");

        JObject root;
        try
        {
            root = BoundedJson.Deserialize<JObject>(body) ?? throw new InvalidDataException();
        }
        catch (Exception ex) when (ex is InvalidDataException or Newtonsoft.Json.JsonException)
        {
            return Result(IntelVerdicts.Unknown, null, "Unreadable response");
        }

        switch (service)
        {
            case IntelServices.VirusTotal:
            {
                var stats = root.SelectToken("data.attributes.last_analysis_stats") as JObject;
                if (stats is null) return Result(IntelVerdicts.Unknown, null, "No analysis statistics");
                int Count(string name) => stats.Value<int?>(name) is int n and >= 0 ? n : 0;
                var malicious = Count("malicious");
                var suspicious = Count("suspicious");
                var total = malicious + suspicious + Count("harmless") + Count("undetected");
                var verdict = malicious >= 3 ? IntelVerdicts.Malicious
                    : malicious >= 1 || suspicious >= 2 ? IntelVerdicts.Suspicious
                    : total > 0 ? IntelVerdicts.Clean : IntelVerdicts.Unknown;
                return Result(verdict, malicious, $"{malicious} malicious, {suspicious} suspicious of {total} engines");
            }
            case IntelServices.AbuseIpDb:
            {
                var score = root.SelectToken("data.abuseConfidenceScore")?.Value<int?>();
                var reports = root.SelectToken("data.totalReports")?.Value<int?>() ?? 0;
                if (score is not (>= 0 and <= 100)) return Result(IntelVerdicts.Unknown, null, "No confidence score");
                var verdict = score >= 75 ? IntelVerdicts.Malicious : score >= 25 ? IntelVerdicts.Suspicious : IntelVerdicts.Clean;
                return Result(verdict, score, $"Abuse confidence {score}% from {reports} reports");
            }
            default:
            {
                var classification = root.Value<string>("classification")?.ToLowerInvariant();
                var riot = root.Value<bool?>("riot") == true;
                var name = root.Value<string>("name") ?? "";
                var verdict = classification == "malicious" ? IntelVerdicts.Malicious
                    : classification == "benign" || riot ? IntelVerdicts.Clean
                    : IntelVerdicts.Unknown;
                return Result(verdict, null, $"Classification {classification ?? "unknown"}{(riot ? ", known business service" : "")}{(name.Length > 0 && name != "unknown" ? $" ({name})" : "")}");
            }
        }
    }
}

public static class IntelStatus
{
    /// <summary>Results worth caching: success or a definite "not found". Auth, quota, and server errors are retried later.</summary>
    public static bool IsCacheable(HttpStatusCode status) => status is HttpStatusCode.OK or HttpStatusCode.NotFound;

    /// <summary>Stop using a service for the rest of a run after an auth or quota failure.</summary>
    public static bool StopsService(HttpStatusCode status) => status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests;
}

/// <summary>Executes one lookup over HTTPS with no redirects, a 10-second timeout, and a 256 KiB response cap.</summary>
public sealed class IntelLookupClient(HttpClient? httpClient = null)
{
    public const int MaximumResponseBytes = 256 * 1024;
    private static readonly HttpClient Shared = new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = Timeout.InfiniteTimeSpan };
    private readonly HttpClient _http = httpClient ?? Shared;

    public async Task<(IntelLookupResult Result, HttpStatusCode Status)> LookupAsync(string service, IntelIndicator indicator, string apiKey, CancellationToken cancellationToken)
    {
        using var request = IntelProviders.BuildRequest(service, indicator, apiKey);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (response.RequestMessage?.RequestUri is not { } uri || uri.Scheme != Uri.UriSchemeHttps ||
            !uri.Host.Equals(IntelProviders.Host(service), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The intel response came from an unexpected source.");
        if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
            throw new InvalidDataException("The intel response exceeds the size limit.");

        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, timeout.Token).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaximumResponseBytes) throw new InvalidDataException("The intel response exceeds the size limit.");
            buffer.Write(chunk, 0, read);
        }
        return (IntelProviders.Parse(service, indicator, response.StatusCode, buffer.ToArray(), DateTimeOffset.UtcNow), response.StatusCode);
    }
}
