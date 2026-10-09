using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Newtonsoft.Json;

namespace Downpour.Tests;

/// <summary>
/// Deterministic fuzzing of every parser that reads untrusted input (downloaded feeds, pipe replies, event fields, audio
/// format blobs, audit lines). Parsers may only return a result or throw their documented exception; anything else
/// (index, overflow, null, format errors) is a bug an attacker-controlled feed or message could trigger.
/// </summary>
public sealed class ParserFuzzTests
{
    private const int Iterations = 400;

    private static readonly string[] Tokens =
    [
        "1.2.3.4", "0.0.0.0", "127.0.0.1", "255.255.255.256", "10.0.0.0/8", "1.2.3.4/33", "::1", "fe80::1%eth0", "2001:db8::/129",
        "example.com", "xn--80ak6aa92e.com", "a..b", "-bad-.com", "http://", "https://evil.example/path?q=1", "hxxp://", "[.]",
        "#", ";", ",", "\t", " ", "\n", "\r\n", "\"", "'", "{", "}", "[", "]", ":", "null", "true", "-1", "0", "1e309",
        "99999999999999999999999", "NaN", "\u202e", "\u0000", "\uFEFF", "𝔘", "ip:port", "1.2.3.4:99999", "AS13335", "ZZ",
        new string('a', 300), new string('9', 40), "\\", "%SystemRoot%", "\\??\\", "C:\\x y\\z.sys", "\"C:\\a\"", "cmd /c", ".exe",
    ];

    private static readonly string[] JsonKeys =
    [
        "ioc", "ioc_value", "ioc_type", "threat_type", "malware", "malware_printable", "confidence_level", "first_seen", "tags",
        "Id", "Name", "Category", "KnownVulnerableSamples", "Filename", "SHA256", "MD5", "Authentihash", "Commands", "Command",
        "Usecase", "Full_Path", "Path", "data", "query_status", "cidr", "sblid", "rir", "vulnerabilities", "cveID", "dateAdded",
        "dueDate", "catalogVersion", "dateReleased", "count", "schemaVersion", "devices", "sessions", "effects", "posture", "issues",
    ];

    private static string Soup(Random random, int maxTokens)
    {
        var builder = new StringBuilder();
        var count = random.Next(1, maxTokens);
        for (var i = 0; i < count; i++) builder.Append(Tokens[random.Next(Tokens.Length)]);
        return builder.ToString();
    }

    private static string Json(Random random, int depth)
    {
        if (depth > 40 || random.Next(4) == 0)
            return random.Next(6) switch
            {
                0 => "null",
                1 => random.Next(-5, 1_000_000).ToString(),
                2 => "1e999",
                3 => random.Next(2) == 0 ? "true" : "false",
                _ => JsonConvert.ToString(Soup(random, 4)),
            };
        if (random.Next(2) == 0)
            return "[" + string.Join(",", Enumerable.Range(0, random.Next(0, 4)).Select(_ => Json(random, depth + 1))) + "]";
        return "{" + string.Join(",", Enumerable.Range(0, random.Next(0, 5)).Select(_ =>
            $"{JsonConvert.ToString(JsonKeys[random.Next(JsonKeys.Length)])}:{Json(random, depth + random.Next(1, 8))}")) + "}";
    }

    private static byte[] Mutate(Random random, byte[] seed)
    {
        var bytes = seed.ToArray();
        var edits = random.Next(1, 8);
        for (var i = 0; i < edits && bytes.Length > 0; i++)
        {
            switch (random.Next(4))
            {
                case 0: bytes[random.Next(bytes.Length)] ^= (byte)(1 << random.Next(8)); break;
                case 1: bytes = bytes[..random.Next(bytes.Length)]; break;
                case 2: bytes = [.. bytes, .. Encoding.UTF8.GetBytes(Tokens[random.Next(Tokens.Length)])]; break;
                default: bytes[random.Next(bytes.Length)] = (byte)random.Next(256); break;
            }
        }
        return bytes.Length == 0 ? [0] : bytes;
    }

    private static IEnumerable<byte[]> Inputs(Random random, bool json)
    {
        for (var i = 0; i < Iterations; i++)
        {
            yield return (i % 5) switch
            {
                0 => Enumerable.Range(0, random.Next(1, 2048)).Select(_ => (byte)random.Next(256)).ToArray(),
                1 => Encoding.UTF8.GetBytes(string.Join("\n", Enumerable.Range(0, random.Next(1, 60)).Select(_ => Soup(random, 6)))),
                2 => Encoding.UTF8.GetBytes(Json(random, 0)),
                3 => Mutate(random, Encoding.UTF8.GetBytes(json ? Json(random, 0) : "1.2.3.4\nexample.com\n# comment\n5.6.7.0/24\n")),
                _ => Encoding.UTF8.GetBytes(new string('[', random.Next(30, 200)) + new string(']', random.Next(0, 200))),
            };
        }
    }

    private static void OnlyDocumented(Action action, params Type[] allowed)
    {
        try { action(); }
        catch (Exception ex) when (allowed.Any(type => type.IsInstanceOfType(ex))) { }
    }

    [Fact]
    public void ThreatFeedParsersOnlyFailWithInvalidData()
    {
        var random = new Random(20261008);
        var watch = Stopwatch.StartNew();
        foreach (var feed in ThreatFeedCatalog.All.Where(f => f.Format != ThreatFeedFormat.Ip2AsnGzip))
        {
            var json = feed.Format is ThreatFeedFormat.ThreatFoxJson or ThreatFeedFormat.LolDriversJson or ThreatFeedFormat.LolbasJson or ThreatFeedFormat.SpamhausJsonLines;
            foreach (var input in Inputs(random, json))
                OnlyDocumented(() => ThreatFeedParser.Parse(feed, input), typeof(InvalidDataException));
        }
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(60), $"Fuzzing took {watch.Elapsed}; a parser may be super-linear.");
    }

    [Fact]
    public void IpOriginDatabaseOnlyFailsWithInvalidData()
    {
        var random = new Random(7);
        var feed = ThreatFeedCatalog.All.First(f => f.Format == ThreatFeedFormat.Ip2AsnGzip);
        foreach (var input in Inputs(random, json: false))
        {
            OnlyDocumented(() => IpOriginDatabase.Parse(input), typeof(InvalidDataException));
            using var buffer = new MemoryStream();
            using (var gzip = new GZipStream(buffer, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(input);
            OnlyDocumented(() => ThreatFeedParser.Parse(feed, buffer.ToArray()), typeof(InvalidDataException));
        }
        var rows = string.Join("\n", Enumerable.Range(0, 200).Select(i => i % 7 == 0 ? Soup(random, 5) : $"1.0.{i}.0\t1.0.{i}.255\t{13335 + i}\tUS\tNET {i}"));
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(Encoding.UTF8.GetBytes(rows));
        OnlyDocumented(() => IpOriginDatabase.Parse(compressed.ToArray()), typeof(InvalidDataException));
    }

    [Fact]
    public void KevCatalogOnlyFailsWithInvalidData()
    {
        var random = new Random(11);
        foreach (var input in Inputs(random, json: true))
            OnlyDocumented(() => KevCatalogClient.Parse(input), typeof(InvalidDataException));
    }

    [Fact]
    public void PipeRepliesNeverCrashValidators()
    {
        var random = new Random(42);
        var reader = new[] { typeof(InvalidDataException), typeof(JsonReaderException), typeof(JsonSerializationException) };
        foreach (var input in Inputs(random, json: true))
        {
            OnlyDocumented(() => { if (BoundedJson.Deserialize<AudioSnapshot>(input) is { } s) _ = AudioClient.IsValid(s); }, reader);
            OnlyDocumented(() => { if (BoundedJson.Deserialize<AntiStalkerSnapshot>(input) is { } s) _ = AntiStalkerClient.IsValid(s); }, reader);
            OnlyDocumented(() => { if (BoundedJson.Deserialize<SecurityEventSnapshot>(input) is { } s) _ = SecurityEventClient.IsValidSnapshot(s); }, reader);
            OnlyDocumented(() => BoundedJson.Deserialize<SecurityAlertSnapshot>(input), reader);
            OnlyDocumented(() => BoundedJson.Deserialize<ThreatDatabaseResponse>(input), reader);
            OnlyDocumented(() => LocalLearningClient.IsValid(BoundedJson.Deserialize<LocalLearningSnapshot>(input), DateTimeOffset.UtcNow), reader);
            OnlyDocumented(() => LocalLearningEngine.IsValidHistory(BoundedJson.Deserialize<LocalLearningHistory>(input), DateTimeOffset.UtcNow), reader);
        }
    }

    [Fact]
    public void TotalHelpersNeverThrow()
    {
        var random = new Random(99);
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        for (var i = 0; i < Iterations * 4; i++)
        {
            var text = random.Next(3) == 0 ? Encoding.UTF8.GetString(Enumerable.Range(0, random.Next(0, 300)).Select(_ => (byte)random.Next(256)).ToArray()) : Soup(random, 12);
            _ = ThreatFeedParser.TryClassify(text, out _);
            _ = PersistenceAnalyzer.CommandTarget(text);
            _ = PersistenceAnalyzer.SignerDisplay(text);
            _ = ServiceInstallAnalyzer.NormalizeImagePath(text);
            _ = ServiceInstallAnalyzer.Assess("HIGH", text, text, random.Next(2) == 0 ? null : text, null);
            _ = AudioThreatAnalyzer.ClassifyKind(text, text, text, random.Next(-2, 12));
            _ = AudioThreatAnalyzer.DescribeFormat(Encoding.UTF8.GetBytes(text));
            _ = AuditChain.Verify(text.Split('\n'), key, random.Next(2) == 0 ? null : random.Next(-5, 50), text, random.Next(-3, 5));
        }
    }
}
