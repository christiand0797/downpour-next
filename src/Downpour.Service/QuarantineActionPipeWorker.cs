using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Append-only, tamper-evident audit of every action request (quarantine, termination, firewall, USB, host isolation),
/// including denials. Records are chained with HMAC-SHA256 (<see cref="AuditChain"/>) under a random key protected
/// with DPAPI for the current user, and the head is kept in a MAC'd anchor so deleted, edited, reordered or truncated
/// records are detected. Bounded to 1 MiB with one rollover; the anchor records where the kept window starts.
/// Limits: code running as this user can use the same DPAPI key, so this proves integrity against offline edits,
/// copies and careless tampering, not against malware already running as the user.
/// </summary>
public sealed class ActionAuditLog(string path)
{
    private const long MaximumBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();
    private bool _loaded;
    private byte[]? _key;
    private string? _keyProblem;
    private long _sequence;
    private string _head = AuditChain.Genesis;
    private long _oldest = 1;

    public static ActionAuditLog CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var file = Path.Combine(root, "action-audit.v1.jsonl");
        foreach (var existing in new[] { file, file + ".1", file + ".key", file + ".anchor" }) SecureJournalDirectory.RestrictExistingFile(existing);
        return new ActionAuditLog(file);
    }

    public string FilePath => path;
    private string KeyPath => path + ".key";
    private string AnchorPath => path + ".anchor";
    private string RolledPath => path + ".1";

    public void Record(string operation, string resultCode, string? objectId, string? fileName)
    {
        var body = JsonSerializer.Serialize(new { at = DateTimeOffset.UtcNow, operation, resultCode, objectId, fileName });
        lock (_gate)
        {
            // Several writers (the service's brokers, a scheduled host-isolation release) may share this file: each append
            // takes a machine-wide lock and re-reads the head from disk so the chain never forks.
            using var mutex = new Mutex(false, MutexName);
            var owned = false;
            try
            {
                try { owned = mutex.WaitOne(TimeSpan.FromSeconds(5)); }
                catch (AbandonedMutexException) { owned = true; }
                _loaded = false;
                EnsureLoaded();
                if (File.Exists(path) && new FileInfo(path).Length > MaximumBytes)
                {
                    File.Move(path, RolledPath, overwrite: true);
                    _oldest = FirstSequence(RolledPath) ?? _sequence + 1;
                }
                if (_key is null)
                {
                    // Never lose an audit record: without the key it is written unchained and the next check reports it.
                    File.AppendAllText(path, body + "\n");
                    return;
                }
                var line = AuditChain.Line(_key, _sequence + 1, _head, body, out var mac);
                File.AppendAllText(path, line + "\n");
                _sequence++;
                _head = mac;
                WriteAnchor();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or IntelKeyStore.CryptographicFailure) { }
            finally
            {
                if (owned) mutex.ReleaseMutex();
            }
        }
    }

    private string MutexName => @"Local\DownpourNext.ActionAudit." + Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant())))[..16];

    public IReadOnlyList<string> ReadRecent(int count) =>
        File.Exists(path) ? File.ReadLines(path).TakeLast(count).ToArray() : [];

    /// <summary>Re-reads the whole retained log and checks every link, the anchor and the kept-window start.</summary>
    public AuditVerification Verify()
    {
        lock (_gate)
        {
            try
            {
                _loaded = false;
                EnsureLoaded();
                var lines = (File.Exists(RolledPath) ? File.ReadLines(RolledPath) : []).Concat(File.Exists(path) ? File.ReadLines(path) : []).ToList();
                if (_key is null)
                {
                    var anyChained = lines.Any(line => line.Contains("\"mac\":", StringComparison.Ordinal));
                    return new AuditVerification(lines.Count, 0, lines.Count, !anyChained, anyChained ? 1 : null, 0, AuditChain.Genesis,
                        anyChained ? $"Audit log cannot be verified: {_keyProblem}" : "No chained records yet.");
                }
                var anchor = ReadAnchor(out var anchorProblem);
                if (anchorProblem is not null)
                    return new AuditVerification(lines.Count, 0, 0, false, null, 0, AuditChain.Genesis, $"Audit log integrity check failed: {anchorProblem}.");
                return AuditChain.Verify(lines, _key, anchor?.Seq, anchor?.Head, anchor?.Oldest ?? 1);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return new AuditVerification(0, 0, 0, false, null, 0, AuditChain.Genesis, $"Audit log could not be read ({ex.GetType().Name}).");
            }
        }
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        var tail = LastChained(path) ?? LastChained(RolledPath);
        if (_key is null && _keyProblem is null) LoadKey(tail is not null);
        _sequence = tail?.Seq ?? 0;
        _head = tail?.Mac ?? AuditChain.Genesis;
        _oldest = 1;
        if (_key is not null && ReadAnchor(out _) is { } anchor)
        {
            _oldest = anchor.Oldest;
            // Continue from the anchor when the tail was cut off, so the gap stays visible instead of being papered over.
            if (anchor.Seq > _sequence) { _sequence = anchor.Seq; _head = anchor.Head; }
        }
    }

    private void LoadKey(bool chainExists)
    {
        try
        {
            if (File.Exists(KeyPath)) _key = IntelKeyStore.Unprotect(File.ReadAllBytes(KeyPath));
            else if (!chainExists)
            {
                _key = RandomNumberGenerator.GetBytes(32);
                File.WriteAllBytes(KeyPath, IntelKeyStore.Protect(_key));
            }
            else _keyProblem = "its key file is missing";
        }
        catch (IntelKeyStore.CryptographicFailure)
        {
            _key = null;
            _keyProblem = "its key cannot be unlocked by this Windows account";
        }
        if (_key is { Length: not 32 }) { _key = null; _keyProblem = "its key file is damaged"; }
    }

    private sealed record Anchor(long Seq, string Head, long Oldest, string Mac);

    private void WriteAnchor()
    {
        var mac = AuditChain.AnchorMac(_key!, _sequence, $"{_head}|{_oldest}");
        var temp = AnchorPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(new Anchor(_sequence, _head, _oldest, mac), Json));
        File.Move(temp, AnchorPath, overwrite: true);
    }

    private Anchor? ReadAnchor(out string? problem)
    {
        problem = null;
        if (!File.Exists(AnchorPath)) return null;
        try
        {
            var anchor = new FileInfo(AnchorPath).Length <= 4096 ? JsonSerializer.Deserialize<Anchor>(File.ReadAllText(AnchorPath), Json) : null;
            if (anchor is null || anchor.Head is not { Length: 64 } || anchor.Mac is not { Length: 64 } || anchor.Oldest < 1)
            {
                problem = "the anchor file is damaged";
                return null;
            }
            if (!AuditChain.AnchorMac(_key!, anchor.Seq, $"{anchor.Head}|{anchor.Oldest}").Equals(anchor.Mac, StringComparison.Ordinal))
            {
                problem = "the anchor file was altered";
                return null;
            }
            return anchor;
        }
        catch (JsonException)
        {
            problem = "the anchor file is damaged";
            return null;
        }
    }

    private static (long Seq, string Mac)? LastChained(string file)
    {
        if (!File.Exists(file)) return null;
        foreach (var line in File.ReadLines(file).Reverse())
            if (Parse(line) is { } record) return record;
        return null;
    }

    private static long? FirstSequence(string file)
    {
        foreach (var line in File.ReadLines(file))
            if (Parse(line) is { } record) return record.Seq;
        return null;
    }

    private static (long Seq, string Mac)? Parse(string line)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            return document.RootElement.TryGetProperty("seq", out var seq) && seq.TryGetInt64(out var value)
                && document.RootElement.TryGetProperty("mac", out var mac) && mac.GetString() is { Length: 64 } text
                ? (value, text) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// Applies DN-008 phase 1 policy to one parsed request: switch, caller, consent token, then the executor. Every outcome is
/// audited. No operation other than the five in <see cref="QuarantineOperations"/> exists.
/// </summary>
public sealed partial class QuarantineActionHandler(
    QuarantineExecutor executor,
    QuarantineVault vault,
    SensorSettingsStore settings,
    ActionConsentStore consent,
    ActionAuditLog audit)
{
    public const int MaximumListItems = 500;
    public IReadOnlyList<string> RecoveryNotes { get; set; } = [];

    [GeneratedRegex("^obj-[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ObjectIdPattern();

    public async Task<QuarantineResponse> HandleAsync(QuarantineRequest request, string? callerDenial, CancellationToken token)
    {
        var enabled = settings.Current.QuarantineActions;
        QuarantineResponse Respond(bool accepted, string code, string message, QuarantinePreview? preview = null, IReadOnlyList<QuarantineItem>? items = null, string? objectId = null, string? file = null)
        {
            audit.Record(request.Operation, code, objectId, file);
            return new(1, request.RequestId, accepted, code, message, enabled, preview, items, items is null ? null : RecoveryNotes);
        }

        if (callerDenial is not null) return Respond(false, "denied-caller", callerDenial);
        if (request.Operation == QuarantineOperations.List)
        {
            var items = vault.List().Take(MaximumListItems).Select(manifest => new QuarantineItem(manifest.ObjectId, Path.GetFileName(manifest.OriginalPath),
                manifest.OriginalPath, manifest.Size, manifest.Sha256, manifest.Reason, manifest.QuarantinedAtUtc, manifest.RestoredAtUtc, manifest.RestoredTo)).ToArray();
            return new(1, request.RequestId, true, "listed", $"{items.Length} item(s).", enabled, null, items, RecoveryNotes);
        }
        if (!enabled) return Respond(false, "disabled", "Quarantine actions are turned off in Settings.");

        switch (request.Operation)
        {
            case QuarantineOperations.PreviewQuarantine:
            {
                if (request.Path is null) return Respond(false, "invalid-request", "A file path is required.");
                QuarantineCandidate candidate;
                try { candidate = executor.Inspect(request.Path); }
                catch (QuarantineRejectedException ex) { return Respond(false, ex.Code, ex.Message, file: SafeName(request.Path)); }
                if (candidate.DenyReason is not null)
                    return Respond(false, "denied-protected-path", candidate.DenyReason, new QuarantinePreview(candidate.FinalPath, candidate.Size, "", candidate.DenyReason, null, null), file: SafeName(candidate.FinalPath));
                if (candidate.Size > QuarantineExecutor.MaximumFileBytes)
                    return Respond(false, "denied-too-large", "Files larger than 256 MiB are not quarantined.", file: SafeName(candidate.FinalPath));
                var (consentToken, expires) = consent.Mint(QuarantineOperations.Quarantine, candidate.FinalPath, candidate.Sha256);
                return Respond(true, "preview", "Review and confirm.", new QuarantinePreview(candidate.FinalPath, candidate.Size, candidate.Sha256, null, consentToken, expires), file: SafeName(candidate.FinalPath));
            }
            case QuarantineOperations.Quarantine:
            {
                if (request.Path is null || !consent.TryConsume(request.ConsentToken, QuarantineOperations.Quarantine, request.Path, out var sha))
                    return Respond(false, "denied-consent", "The confirmation expired or did not match. Review the file again.", file: SafeName(request.Path));
                var outcome = await executor.QuarantineAsync(request.Path, sha, "Quarantined by user", token, expectedFinalPath: request.Path);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, objectId: outcome.ObjectId, file: SafeName(request.Path));
            }
            case QuarantineOperations.PreviewRestore:
            {
                if (!TryRestoreTarget(request, out var manifest, out var target, out var error)) return Respond(false, "invalid-request", error, objectId: request.ObjectId);
                if (manifest!.RestoredAtUtc is not null) return Respond(false, "already-restored", "That item was already restored.", objectId: manifest.ObjectId);
                var deny = File.Exists(target) || Directory.Exists(target) ? "A file already exists at the restore location. Choose another location."
                    : QuarantineExecutor.DenyReason(target);
                if (deny is not null)
                    return Respond(false, "denied-target", deny, new QuarantinePreview(target, manifest.Size, manifest.Sha256, deny, null, null), objectId: manifest.ObjectId);
                var (consentToken, expires) = consent.Mint(QuarantineOperations.Restore, manifest.ObjectId + "|" + target, manifest.Sha256);
                return Respond(true, "preview", "Review and confirm.", new QuarantinePreview(target, manifest.Size, manifest.Sha256, null, consentToken, expires), objectId: manifest.ObjectId);
            }
            case QuarantineOperations.Restore:
            {
                if (!TryRestoreTarget(request, out var manifest, out var target, out var error)) return Respond(false, "invalid-request", error, objectId: request.ObjectId);
                if (!consent.TryConsume(request.ConsentToken, QuarantineOperations.Restore, manifest!.ObjectId + "|" + target, out var sha) || sha != manifest.Sha256)
                    return Respond(false, "denied-consent", "The confirmation expired or did not match. Review the restore again.", objectId: manifest.ObjectId);
                if (QuarantineExecutor.DenyReason(target) is { } deny) return Respond(false, "denied-target", deny, objectId: manifest.ObjectId);
                var outcome = await executor.RestoreAsync(manifest.ObjectId, request.RestorePath is null ? null : target, token);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, objectId: manifest.ObjectId);
            }
            default:
                return Respond(false, "invalid-request", "Unknown operation.");
        }
    }

    private bool TryRestoreTarget(QuarantineRequest request, out QuarantineManifest? manifest, out string target, out string error)
    {
        manifest = null;
        target = "";
        error = "";
        if (request.ObjectId is null || !ObjectIdPattern().IsMatch(request.ObjectId) || !vault.TryReadManifest(request.ObjectId, out manifest) || manifest is null)
        {
            error = "That quarantined item does not exist.";
            return false;
        }
        var path = request.RestorePath ?? manifest.OriginalPath;
        if (!IsSafeFullPath(path))
        {
            error = "A full local file path is required.";
            return false;
        }
        target = Path.GetFullPath(path);
        return true;
    }

    internal static bool IsSafeFullPath(string path) =>
        path.Length is > 3 and <= 32_000 && Path.IsPathFullyQualified(path) && path.IndexOf(':', 2) < 0 && !path.Contains('\0')
        && !path.StartsWith(@"\\?\", StringComparison.Ordinal) && !path.StartsWith(@"\\.\", StringComparison.Ordinal);

    private static string? SafeName(string? path)
    {
        try { return path is null ? null : Path.GetFileName(path); }
        catch (ArgumentException) { return null; }
    }
}

/// <summary>Quarantine action endpoint. One request per connection, 96 KiB cap, strict JSON, caller verified per connection.</summary>
public sealed class QuarantineActionPipeWorker(
    QuarantineActionHandler handler,
    QuarantineExecutor executor,
    OperationJournal journal,
    IActionCallerVerifier caller,
    ILogger<QuarantineActionPipeWorker> logger,
    string pipeName = QuarantineClient.PipeName) : BackgroundService
{
    public const int MaximumRequestBytes = 96 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 4 };
    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal) { "schemaVersion", "requestId", "operation", "path", "objectId", "restorePath", "consentToken" };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await journal.InitializeAsync(stoppingToken);
            handler.RecoveryNotes = await executor.RecoverAsync(stoppingToken);
            foreach (var note in handler.RecoveryNotes) logger.LogWarning("Quarantine recovery: {Note}", note);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            // Fail closed: without a working journal no action may run.
            logger.LogError(ex, "Quarantine recovery failed; quarantine actions are unavailable.");
            return;
        }

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
                QuarantineResponse response;
                if (request is null)
                {
                    response = new QuarantineResponse(1, Guid.Empty, false, "invalid-request", "The request was malformed.", false);
                }
                else
                {
                    // Actions may take longer than the read deadline (hashing and encrypting up to 256 MiB).
                    using var actionTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    actionTimeout.CancelAfter(TimeSpan.FromMinutes(5));
                    response = await handler.HandleAsync(request, caller.Verify(pipe), actionTimeout.Token);
                }
                if (response.ResultCode is not ("listed" or "preview"))
                    logger.LogInformation("Quarantine request {Operation}: {ResultCode}.", request?.Operation ?? "invalid", response.ResultCode);
                await JsonSerializer.SerializeAsync(pipe, response, JsonOptions, stoppingToken);
                await pipe.WriteAsync(new byte[] { (byte)'\n' }, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A quarantine client disconnected before completion.");
            }
        }
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
            if (newline >= 0)
            {
                buffer.Write(chunk, 0, newline);
                return buffer.Length == 0 ? null : buffer.ToArray();
            }
            buffer.Write(chunk, 0, read);
        }
        return null;
    }

    internal static QuarantineRequest? ParseStrictRequest(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumRequestBytes) return null;
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!AllowedProperties.Contains(property.Name) || !values.TryAdd(property.Name, property.Value)) return null;
            if (!values.TryGetValue("schemaVersion", out var schema) || !schema.TryGetInt32(out var version) || version != 1
                || !values.TryGetValue("requestId", out var id) || id.ValueKind != JsonValueKind.String || !Guid.TryParseExact(id.GetString(), "D", out var requestId) || requestId == Guid.Empty
                || !values.TryGetValue("operation", out var operation) || operation.ValueKind != JsonValueKind.String || !QuarantineOperations.All.Contains(operation.GetString()!))
                return null;
            string? Text(string name, int max)
            {
                if (!values.TryGetValue(name, out var element) || element.ValueKind == JsonValueKind.Null) return null;
                if (element.ValueKind != JsonValueKind.String) throw new JsonException();
                var text = element.GetString()!;
                return text.Length <= max ? text : throw new JsonException();
            }
            var path = Text("path", 32_000);
            var restorePath = Text("restorePath", 32_000);
            if ((path is not null && !QuarantineActionHandler.IsSafeFullPath(path)) || (restorePath is not null && !QuarantineActionHandler.IsSafeFullPath(restorePath)))
                return null;
            return new QuarantineRequest(1, requestId, operation.GetString()!, path, Text("objectId", 36), restorePath, Text("consentToken", 64));
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
