using System.Net;
using System.Text;
using Downpour.Core;
using Newtonsoft.Json;

namespace Downpour.Tests;

public sealed class EpssClientTests
{
    private const string RequestedCve = "CVE-2026-12345";
    private const string ValidResponse = """
        {"status":"OK","status-code":200,"version":"1.0","total":1,"offset":0,"limit":100,"data":[{"cve":"CVE-2026-12345","epss":"0.125000000","percentile":"0.930000000","date":"2026-10-04"}]}
        """;

    [Fact]
    public void ParseReturnsBoundedScoreAndProvenance()
    {
        var retrieved = new DateTimeOffset(2026, 10, 4, 20, 0, 0, TimeSpan.Zero);

        var result = EpssClient.Parse(Encoding.UTF8.GetBytes(ValidResponse), RequestedCve, retrieved);

        Assert.NotNull(result);
        Assert.Equal(RequestedCve, result.CveId);
        Assert.Equal(0.125m, result.Score);
        Assert.Equal(0.93m, result.Percentile);
        Assert.Equal(new DateOnly(2026, 10, 4), result.ScoreDate);
        Assert.Equal(retrieved, result.RetrievedAtUtc);
    }

    [Fact]
    public void ParseAcceptsNoScoreForValidatedCve()
    {
        const string empty = """{"status":"OK","status-code":200,"total":0,"data":[]}""";

        Assert.Null(EpssClient.Parse(Encoding.UTF8.GetBytes(empty), RequestedCve, DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData("{\"status\":\"OK\",\"status\":\"OK\",\"status-code\":200,\"total\":0,\"data\":[]}")]
    [InlineData("{\"status\":\"OK\",\"status-code\":200,\"total\":2,\"data\":[]}")]
    [InlineData("{\"status\":\"OK\",\"status-code\":200,\"total\":2,\"data\":[{},{}]}")]
    public void ParseRejectsDuplicateOrInconsistentEnvelope(string json) =>
        Assert.ThrowsAny<Exception>(() => EpssClient.Parse(Encoding.UTF8.GetBytes(json), RequestedCve, DateTimeOffset.UtcNow));

    [Theory]
    [InlineData("CVE-2026-54321", "0.1", "0.5", "2026-10-04")]
    [InlineData("CVE-2026-12345", "1.01", "0.5", "2026-10-04")]
    [InlineData("CVE-2026-12345", "-0.1", "0.5", "2026-10-04")]
    [InlineData("CVE-2026-12345", "0.1", "1.5", "2026-10-04")]
    [InlineData("CVE-2026-12345", "0.1", "0.5", "not-a-date")]
    public void ParseRejectsMismatchAndInvalidScoreValues(string cve, string epss, string percentile, string date)
    {
        var json = $"{{\"status\":\"OK\",\"status-code\":200,\"total\":1,\"data\":[{{\"cve\":\"{cve}\",\"epss\":\"{epss}\",\"percentile\":\"{percentile}\",\"date\":\"{date}\"}}]}}";

        Assert.Throws<InvalidDataException>(() => EpssClient.Parse(Encoding.UTF8.GetBytes(json), RequestedCve, DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task FetchUsesFixedHttpsSourceAndSingleValidatedCve()
    {
        var handler = new StubHandler(request =>
        {
            Assert.Equal("https", request.RequestUri!.Scheme);
            Assert.Equal("api.first.org", request.RequestUri.Host);
            Assert.Equal("/data/v1/epss", request.RequestUri.AbsolutePath);
            Assert.Equal("?cve=CVE-2026-12345", request.RequestUri.Query);
            return Json(ValidResponse);
        });

        var result = await new EpssClient(new HttpClient(handler)).FetchAsync(RequestedCve);

        Assert.NotNull(result);
        Assert.Equal(RequestedCve, result.CveId);
    }

    [Fact]
    public async Task FetchRejectsInvalidCveBeforeNetworkRequest()
    {
        var handler = new StubHandler(_ => throw new InvalidOperationException("Unexpected request."));

        await Assert.ThrowsAsync<ArgumentException>(() => new EpssClient(new HttpClient(handler)).FetchAsync("https://attacker.invalid/"));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task FetchRejectsUnexpectedFinalHostAndOversizedResponse()
    {
        var redirected = new StubHandler(request =>
        {
            var response = Json(ValidResponse);
            response.RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://attacker.invalid/data");
            return response;
        });
        await Assert.ThrowsAsync<InvalidDataException>(() => new EpssClient(new HttpClient(redirected)).FetchAsync(RequestedCve));

        var oversized = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[EpssClient.MaximumPayloadBytes + 1])
        });
        await Assert.ThrowsAsync<InvalidDataException>(() => new EpssClient(new HttpClient(oversized)).FetchAsync(RequestedCve));
    }

    private static HttpResponseMessage Json(string value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            var response = respond(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }
}
