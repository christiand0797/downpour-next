using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// One user-started YARA scan at a time over a file or folder. Read-only: files are never modified, moved, or
/// quarantined. Bounded to 100,000 files and 500 stored findings; links and junctions are not followed. Matches become
/// "Downpour/Yara" findings in triage (CRITICAL/HIGH in Threats, the rest in Possible Threats); low-confidence rules
/// are listed in the scan results only.
/// </summary>
public sealed class YaraScanCoordinator(IYaraScannerBackend backend, Func<IReadOnlyList<SecurityFindingObservation>, CancellationToken, Task> ingest, ILogger<YaraScanCoordinator> logger)
{
    public const int MaximumFiles = 100_000;
    public const int MaximumFindings = 500;
    private readonly object _gate = new();
    private YaraScanJob? _job;
    private CancellationTokenSource? _cancel;
    private Task _running = Task.CompletedTask;

    public YaraScanCoordinator(IYaraScannerBackend backend, SecurityAlertRepository alerts, ILogger<YaraScanCoordinator> logger)
        : this(backend, (findings, token) => alerts.IngestFindingsAsync(findings, DateTimeOffset.UtcNow, token), logger) { }

    public YaraScanJob? Current { get { lock (_gate) return _job; } }

    public Task Completion { get { lock (_gate) return _running; } }

    public (bool Started, string Code, string Message) Start(string root, bool recursive)
    {
        if (!IsSafeRoot(root)) return (false, "invalid-path", "Choose a local file or folder.");
        var full = Path.GetFullPath(root);
        var isFile = File.Exists(full);
        if (!isFile && !Directory.Exists(full)) return (false, "not-found", "That file or folder does not exist.");
        lock (_gate)
        {
            if (_job is { State: "starting" or "running" }) return (false, "busy", "A scan is already running.");
            _cancel?.Dispose();
            _cancel = new CancellationTokenSource();
            _job = new YaraScanJob(Guid.NewGuid(), full, recursive && !isFile, "starting", 0, 0, 0, 0, null, DateTimeOffset.UtcNow, null, null, []);
            var token = _cancel.Token;
            _running = Task.Run(() => RunAsync(full, isFile, recursive && !isFile, token));
        }
        return (true, "started", "Scan started.");
    }

    public bool Cancel()
    {
        lock (_gate)
        {
            if (_job is not { State: "starting" or "running" }) return false;
            _cancel?.Cancel();
            return true;
        }
    }

    private void Update(Func<YaraScanJob, YaraScanJob> change)
    {
        lock (_gate) if (_job is not null) _job = change(_job);
    }

    private async Task RunAsync(string root, bool isFile, bool recursive, CancellationToken token)
    {
        var findings = new List<YaraScanFinding>();
        try
        {
            var ready = await backend.EnsureStartedAsync(token);
            if (ready.Fatal is not null)
            {
                Update(job => job with { State = "failed", Message = ready.Fatal, FinishedAtUtc = DateTimeOffset.UtcNow });
                return;
            }
            Update(job => job with { State = "running" });
            IEnumerable<string> files = isFile ? [root] : Directory.EnumerateFiles(root, "*", new EnumerationOptions
            {
                RecurseSubdirectories = recursive,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline | FileAttributes.Device,
                ReturnSpecialDirectories = false,
                MaxRecursionDepth = 32,
            });
            var count = 0;
            foreach (var file in files)
            {
                token.ThrowIfCancellationRequested();
                if (++count > MaximumFiles)
                {
                    Update(job => job with { Message = $"Stopped after {MaximumFiles:N0} files." });
                    break;
                }
                Update(job => job with { FilesQueued = count, CurrentFile = Path.GetFileName(file) });
                var result = await backend.ScanAsync(file, token);
                switch (result.Status)
                {
                    case "matched" when result.Matches.Count > 0:
                        if (findings.Count < MaximumFindings) findings.Add(new YaraScanFinding(file, result.Size, result.Matches));
                        // Only rules that stay quiet on clean Windows files may raise alerts (rule_quality.json).
                        var confident = result.Matches.Where(match => !match.LowConfidence).ToArray();
                        if (confident.Length > 0) await IngestAsync(file, confident, token);
                        Update(job => job with { FilesScanned = job.FilesScanned + 1, Findings = findings.ToArray() });
                        break;
                    case "clean" or "matched":
                        Update(job => job with { FilesScanned = job.FilesScanned + 1 });
                        break;
                    case "skipped":
                        Update(job => job with { FilesSkipped = job.FilesSkipped + 1 });
                        break;
                    default:
                        Update(job => job with { FilesFailed = job.FilesFailed + 1 });
                        break;
                }
            }
            Update(job => job with { State = "completed", CurrentFile = null, FinishedAtUtc = DateTimeOffset.UtcNow, Findings = findings.ToArray() });
        }
        catch (OperationCanceledException)
        {
            Update(job => job with { State = "cancelled", CurrentFile = null, FinishedAtUtc = DateTimeOffset.UtcNow, Findings = findings.ToArray() });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            logger.LogWarning(ex, "A YARA scan stopped early.");
            Update(job => job with { State = "failed", CurrentFile = null, Message = "The scan stopped early: " + ex.Message, FinishedAtUtc = DateTimeOffset.UtcNow, Findings = findings.ToArray() });
        }
    }

    private Task IngestAsync(string path, IReadOnlyList<YaraRuleMatch> matches, CancellationToken token)
    {
        var top = matches.OrderBy(match => Rank(match.Severity)).First();
        var rules = string.Join(", ", matches.Select(match => match.Rule).Distinct().Take(5));
        var technique = matches.Select(match => match.Technique).FirstOrDefault(value => value.Length > 0) ?? "YARA";
        var finding = SecurityFindingMapper.Create(SecurityFindingCatalog.Yara, "YARA match", top.Severity, technique,
            $"YARA rule {rules} matched {Path.GetFileName(path)}", path);
        return ingest([finding], token);
    }

    private static int Rank(string severity) => severity switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3 };

    internal static bool IsSafeRoot(string? path) =>
        path is { Length: > 2 and <= 32_000 } && Path.IsPathFullyQualified(path) && path.IndexOf(':', 2) < 0 && !path.Contains('\0')
        && !path.StartsWith(@"\\?\", StringComparison.Ordinal) && !path.StartsWith(@"\\.\", StringComparison.Ordinal);
}

/// <summary>Read-only YARA scan endpoint (Downpour.YaraScan.v1): status, start, cancel. Strict JSON, 64 KiB cap, current-user ACL.</summary>
public sealed class YaraScanPipeWorker(
    YaraScanCoordinator coordinator,
    IYaraScannerBackend backend,
    ILogger<YaraScanPipeWorker> logger,
    string pipeName = YaraScanClient.PipeName) : BackgroundService
{
    private const int MaximumRequestBytes = 64 * 1024;
    // Response -> Job -> Findings[] -> Matches[] -> Tags[] nests about 8 levels; 16 leaves headroom.
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 16 };
    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal) { "schemaVersion", "requestId", "operation", "path", "recursive" };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.WriteThrough, 4096, 4096,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());
                await pipe.WaitForConnectionAsync(stoppingToken);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                var line = await ReadLineAsync(pipe, timeout.Token);
                var request = line is null ? null : ParseStrictRequest(line);
                var response = request is null
                    ? new YaraScanResponse(1, Guid.Empty, false, "invalid-request", "The request was malformed.", false, null, 0, null, null)
                    : Handle(request);
                await JsonSerializer.SerializeAsync(pipe, response, JsonOptions, timeout.Token);
                await pipe.WriteAsync(new byte[] { (byte)'\n' }, timeout.Token);
                await pipe.FlushAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A YARA scan client disconnected before completion.");
            }
            catch (Exception exception) when (exception is JsonException or NotSupportedException or InvalidOperationException && !stoppingToken.IsCancellationRequested)
            {
                // A reply that cannot be written must never stop the host (BackgroundService failures end the service).
                logger.LogWarning(exception, "A YARA scan reply could not be written.");
            }
        }
    }

    internal YaraScanResponse Handle(YaraScanRequest request)
    {
        var (accepted, code, message) = request.Operation switch
        {
            YaraScanOperations.Start => coordinator.Start(request.Path!, request.Recursive),
            YaraScanOperations.Cancel => coordinator.Cancel() ? (true, "cancelling", "Cancelling the scan.") : (false, "not-running", "No scan is running."),
            _ => (true, "status", ""),
        };
        var ready = backend.Ready;
        // Start the helper in the background on first contact so the Scanner screen can show which rules loaded.
        if (ready is null) _ = backend.EnsureStartedAsync(CancellationToken.None);
        return new YaraScanResponse(1, request.RequestId, accepted, code, message, ready is { Fatal: null }, ready?.EngineVersion, ready?.RuleCount ?? 0,
            ready?.RuleFiles, coordinator.Current, ready?.LowConfidenceRules ?? 0);
    }

    private static async Task<byte[]?> ReadLineAsync(Stream pipe, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        while (buffer.Length <= MaximumRequestBytes)
        {
            var read = await pipe.ReadAsync(chunk, token);
            if (read == 0) return null;
            var newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
            buffer.Write(chunk, 0, newline >= 0 ? newline : read);
            if (newline >= 0) return buffer.Length == 0 ? null : buffer.ToArray();
        }
        return null;
    }

    internal static YaraScanRequest? ParseStrictRequest(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumRequestBytes) return null;
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!AllowedProperties.Contains(property.Name) || !values.TryAdd(property.Name, property.Value)) return null;
            if (!values.TryGetValue("schemaVersion", out var schema) || !schema.TryGetInt32(out var version) || version != 1
                || !values.TryGetValue("requestId", out var id) || id.ValueKind != JsonValueKind.String || !Guid.TryParseExact(id.GetString(), "D", out var requestId) || requestId == Guid.Empty
                || !values.TryGetValue("operation", out var operation) || operation.ValueKind != JsonValueKind.String || !YaraScanOperations.All.Contains(operation.GetString()!))
                return null;
            string? path = null;
            if (values.TryGetValue("path", out var pathElement) && pathElement.ValueKind != JsonValueKind.Null)
            {
                if (pathElement.ValueKind != JsonValueKind.String || !YaraScanCoordinator.IsSafeRoot(pathElement.GetString())) return null;
                path = pathElement.GetString();
            }
            var recursive = false;
            if (values.TryGetValue("recursive", out var recursiveElement))
            {
                if (recursiveElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return null;
                recursive = recursiveElement.GetBoolean();
            }
            if (operation.GetString() == YaraScanOperations.Start && path is null) return null;
            return new YaraScanRequest(1, requestId, operation.GetString()!, path, recursive);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
