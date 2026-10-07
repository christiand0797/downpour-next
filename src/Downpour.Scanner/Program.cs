using System.Buffers;
using System.Text;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Scanner;

// Downpour.Scanner: isolated YARA-X helper (DN-026). Started only by the sensor service, inside a job object. Takes no
// arguments, loads only the bundled rules next to it, reads one JSON request per stdin line, writes one JSON result per
// stdout line, and exits when stdin closes. It never writes, moves, or deletes the files it scans.
var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
using var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
using var stdin = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));

void Write<T>(T value) => stdout.WriteLine(JsonSerializer.Serialize(value, json));

if (YaraX.EnsureLoaded() is { } loadError)
{
    Write(new ScannerReady(1, YaraX.PinnedVersion, 0, [], loadError));
    return 3;
}

YaraEngine engine;
try
{
    engine = YaraEngine.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "yara_rules"));
    engine.LowConfidence = RuleQuality.Load(Path.Combine(AppContext.BaseDirectory, "rule_quality.json"));
}
catch (InvalidOperationException ex)
{
    Write(new ScannerReady(1, YaraX.PinnedVersion, 0, [], ex.Message));
    return 4;
}

using (engine)
{
    Write(new ScannerReady(1, YaraX.PinnedVersion, engine.RuleCount, engine.RuleFiles, null, engine.LowConfidence.Count));
    while (await ReadBoundedLineAsync(stdin) is { } line)
    {
        ScannerFileRequest? request;
        try { request = JsonSerializer.Deserialize<ScannerFileRequest>(line, json); }
        catch (JsonException) { request = null; }
        if (request is null) { Write(new ScannerFileResult(-1, "error", "Malformed request.", 0, [])); continue; }
        Write(ScanFile(engine, request));
    }
}
return 0;

static ScannerFileResult ScanFile(YaraEngine engine, ScannerFileRequest request)
{
    const long maximumBytes = 256L * 1024 * 1024;
    var path = request.Path;
    if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || path.IndexOf(':', 2) >= 0 || path.StartsWith(@"\\.\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal))
        return new(request.Id, "skipped", "Not a local file path.", 0, []);
    byte[]? buffer = null;
    try
    {
        using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.ReadWrite | FileShare.Delete,
            Options = FileOptions.SequentialScan,
        });
        var length = stream.Length;
        if (length > maximumBytes) return new(request.Id, "skipped", "Larger than 256 MiB.", length, []);
        buffer = ArrayPool<byte>.Shared.Rent((int)Math.Max(1, length));
        var read = 0;
        while (read < length)
        {
            var got = stream.Read(buffer, read, (int)length - read);
            if (got == 0) break;
            read += got;
        }
        var (status, message, matches) = engine.Scan(buffer.AsSpan(0, read));
        return new(request.Id, status, message, read, matches);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
    {
        return new(request.Id, "skipped", ex.GetType() == typeof(UnauthorizedAccessException) ? "Access denied." : "The file could not be read.", 0, []);
    }
    finally
    {
        if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
    }
}

static async Task<string?> ReadBoundedLineAsync(StreamReader reader)
{
    var line = await reader.ReadLineAsync();
    return line is { Length: > 65_536 } ? "" : line;
}
