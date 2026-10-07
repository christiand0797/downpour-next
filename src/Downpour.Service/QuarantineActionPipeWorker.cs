using System.IO.Pipes;
using System.Text.Json;
using System.Text.RegularExpressions;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>Append-only JSON-lines audit of every quarantine request, including denials. Bounded to 1 MiB with one rollover.</summary>
public sealed class ActionAuditLog(string path)
{
    private const long MaximumBytes = 1024 * 1024;
    private readonly object _gate = new();

    public static ActionAuditLog CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var file = Path.Combine(root, "action-audit.v1.jsonl");
        SecureJournalDirectory.RestrictExistingFile(file);
        return new ActionAuditLog(file);
    }

    public string FilePath => path;

    public void Record(string operation, string resultCode, string? objectId, string? fileName)
    {
        var line = JsonSerializer.Serialize(new { at = DateTimeOffset.UtcNow, operation, resultCode, objectId, fileName }) + "\n";
        lock (_gate)
        {
            try
            {
                if (File.Exists(path) && new FileInfo(path).Length > MaximumBytes) File.Move(path, path + ".1", overwrite: true);
                File.AppendAllText(path, line);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    public IReadOnlyList<string> ReadRecent(int count) =>
        File.Exists(path) ? File.ReadLines(path).TakeLast(count).ToArray() : [];
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
