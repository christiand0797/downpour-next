using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>
/// Handles emergency host isolation requests (DN-008 Phase 5).
/// Enforces caller authentication, feature switches, single-use consent tokens, auto-expiry bounds, and audit logging.
/// </summary>
public sealed class HostIsolationHandler(
    HostIsolationExecutor executor,
    SensorSettingsStore settings,
    ActionConsentStore consent,
    ActionAuditLog audit)
{
    public async Task<HostIsolationResponse> HandleAsync(
        HostIsolationRequest request,
        string? callerDenial,
        CancellationToken token)
    {
        var enabled = settings.Current.HostIsolationActions;

        HostIsolationResponse Respond(
            bool accepted,
            string code,
            string message,
            bool isIsolated,
            DateTimeOffset? activeUntilUtc = null,
            IReadOnlyList<string>? rulesCreated = null,
            HostIsolationPreview? preview = null)
        {
            audit.Record(request.Operation, code, "host", request.Reason);
            return new HostIsolationResponse(1, request.RequestId, accepted, code, message, enabled, isIsolated, activeUntilUtc, rulesCreated, preview);
        }

        if (callerDenial is not null)
            return Respond(false, "denied-caller", callerDenial, executor.IsIsolated, executor.ActiveUntilUtc);

        if (!enabled)
            return Respond(false, "disabled", "Host isolation actions are turned off in Settings.", executor.IsIsolated, executor.ActiveUntilUtc);

        switch (request.Operation)
        {
            case HostIsolationOperations.GetStatus:
            {
                var isIso = executor.IsIsolated;
                var until = executor.ActiveUntilUtc;
                var rules = executor.CurrentState?.RulesCreated;
                return Respond(true, isIso ? "isolated" : "normal", isIso ? $"Host is isolated until {until:HH:mm:ss} UTC." : "Host network traffic is normal.", isIso, until, rules);
            }

            case HostIsolationOperations.PreviewIsolate:
            {
                var (allowed, denyReason) = executor.ValidateDuration(request.DurationMinutes);
                if (!allowed)
                {
                    var deniedPreview = new HostIsolationPreview(
                        request.Operation,
                        request.DurationMinutes,
                        null,
                        request.LockWorkstation,
                        denyReason,
                        null,
                        [],
                        [],
                        []);
                    return Respond(false, "denied-invalid-duration", denyReason ?? "Invalid isolation duration.", executor.IsIsolated, executor.ActiveUntilUtc, preview: deniedPreview);
                }

                var targetKey = $"isolate|{request.DurationMinutes}|{request.LockWorkstation}";
                var (consentToken, tokenExpires) = consent.Mint(
                    HostIsolationOperations.Isolate,
                    targetKey,
                    "Host Network Isolation");

                var expectedEffects = new List<string>
                {
                    $"Create inbound and outbound Windows Firewall isolation rules dropping all non-loopback network packets for {request.DurationMinutes} minutes",
                    "Preserve local loopback traffic (127.0.0.1 and ::1) to ensure local IPC and Downpour remain operational",
                    $"Engage automatic expiration timer to ensure host isolation automatically releases at {DateTimeOffset.UtcNow.AddMinutes(request.DurationMinutes):HH:mm:ss} UTC",
                    "Record host isolation event and expiration time in the append-only action audit log"
                };

                if (request.LockWorkstation)
                {
                    expectedEffects.Add("Lock the active Windows workstation session via user32.dll");
                }

                var risks = new List<string>
                {
                    "All external network connectivity, internet access, LAN communications, and remote desktop sessions will be terminated immediately",
                    "Active downloads, cloud sync, and network-dependent services will fail until isolation is released"
                };

                var rollbackSteps = new List<string>
                {
                    "Isolation will automatically expire and restore connectivity; operator can also manually release isolation at any time via Emergency or Remediation page"
                };

                var preview = new HostIsolationPreview(
                    request.Operation,
                    request.DurationMinutes,
                    DateTimeOffset.UtcNow.AddMinutes(request.DurationMinutes),
                    request.LockWorkstation,
                    null,
                    consentToken,
                    expectedEffects,
                    risks,
                    rollbackSteps);

                return Respond(true, "preview-generated", "Consent token minted. Action preview ready for operator confirmation.", executor.IsIsolated, executor.ActiveUntilUtc, preview: preview);
            }

            case HostIsolationOperations.Isolate:
            {
                var targetKey = $"isolate|{request.DurationMinutes}|{request.LockWorkstation}";
                if (!consent.TryConsume(request.ConsentToken, HostIsolationOperations.Isolate, targetKey, out _))
                {
                    return Respond(false, "denied-consent", "Consent token is missing, expired, or does not match this operation and parameters.", executor.IsIsolated, executor.ActiveUntilUtc);
                }

                var outcome = executor.Isolate(request.DurationMinutes, request.LockWorkstation, request.Reason);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, outcome.Succeeded, outcome.ExpiresAtUtc, outcome.RulesCreated);
            }

            case HostIsolationOperations.PreviewRelease:
            {
                var (consentToken, tokenExpires) = consent.Mint(
                    HostIsolationOperations.Release,
                    "release-host-isolation",
                    "Release Host Isolation");

                var expectedEffects = new List<string>
                {
                    "Remove Windows Firewall host isolation rules across all network profiles",
                    "Cancel active automatic expiration timer",
                    "Restore standard inbound and outbound network connectivity",
                    "Record isolation release event in the append-only action audit log"
                };

                var risks = new List<string>
                {
                    "If active malware or threat remains on the host, command-and-control communication may resume upon reconnection"
                };

                var rollbackSteps = new List<string>
                {
                    "Re-engage emergency host isolation if active malicious traffic or exfiltration continues"
                };

                var preview = new HostIsolationPreview(
                    request.Operation,
                    0,
                    null,
                    false,
                    null,
                    consentToken,
                    expectedEffects,
                    risks,
                    rollbackSteps);

                return Respond(true, "preview-generated", "Consent token minted. Release preview ready for operator confirmation.", executor.IsIsolated, executor.ActiveUntilUtc, preview: preview);
            }

            case HostIsolationOperations.Release:
            {
                if (!consent.TryConsume(request.ConsentToken, HostIsolationOperations.Release, "release-host-isolation", out _))
                {
                    return Respond(false, "denied-consent", "Consent token is missing, expired, or does not match this operation.", executor.IsIsolated, executor.ActiveUntilUtc);
                }

                var outcome = executor.Release(request.Reason);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, false);
            }

            default:
                return Respond(false, "invalid-operation", $"Unknown operation '{request.Operation}'.", executor.IsIsolated, executor.ActiveUntilUtc);
        }
    }
}

/// <summary>
/// Named pipe worker for emergency host isolation requests on 'Downpour.HostIsolation.v1'.
/// </summary>
public sealed class HostIsolationPipeWorker(
    HostIsolationHandler handler,
    IActionCallerVerifier callerVerifier,
    ILogger<HostIsolationPipeWorker> logger) : BackgroundService
{
    public const string PipeName = "Downpour.HostIsolation.v1";
    private const int MaximumRequestBytes = 32 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "requestId", "operation", "durationMinutes", "lockWorkstation", "reason", "consentToken"
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    PipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    4096,
                    4096,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());

                await pipe.WaitForConnectionAsync(stoppingToken);

                var callerDenial = callerVerifier.Verify(pipe);
                var requestBytes = await ReadLineAsync(pipe, stoppingToken);
                HostIsolationResponse response;

                if (requestBytes is null)
                {
                    response = new HostIsolationResponse(1, Guid.Empty, false, "invalid-request", "Request body was empty or exceeded size limit.", false, false);
                }
                else
                {
                    var request = ParseStrictRequest(requestBytes);
                    if (request is null)
                    {
                        response = new HostIsolationResponse(1, Guid.Empty, false, "malformed-request", "Request failed schema or parameter validation.", false, false);
                    }
                    else
                    {
                        response = await handler.HandleAsync(request, callerDenial, stoppingToken);
                    }
                }

                var responseBytes = JsonSerializer.SerializeToUtf8Bytes(response, Json);
                await pipe.WriteAsync(responseBytes, stoppingToken);
                pipe.WriteByte((byte)'\n');
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (IOException ex)
            {
                logger.LogDebug(ex, "A host isolation client disconnected before completion.");
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException && !stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(ex, "A host isolation reply could not be written.");
            }
            finally
            {
                pipe?.Dispose();
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

    internal static HostIsolationRequest? ParseStrictRequest(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumRequestBytes) return null;
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                MaxDepth = 4,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });

            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;

            var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!AllowedProperties.Contains(property.Name) || !values.TryAdd(property.Name, property.Value))
                    return null;
            }

            if (!values.TryGetValue("schemaVersion", out var schema) || !schema.TryGetInt32(out var version) || version != 1
                || !values.TryGetValue("requestId", out var id) || id.ValueKind != JsonValueKind.String || !Guid.TryParseExact(id.GetString(), "D", out var requestId) || requestId == Guid.Empty
                || !values.TryGetValue("operation", out var op) || op.ValueKind != JsonValueKind.String || !HostIsolationOperations.All.Contains(op.GetString()!))
            {
                return null;
            }

            string? Text(string name, int max)
            {
                if (!values.TryGetValue(name, out var element) || element.ValueKind == JsonValueKind.Null) return null;
                if (element.ValueKind != JsonValueKind.String) throw new JsonException();
                var text = element.GetString()!;
                return text.Length <= max ? text : throw new JsonException();
            }

            int durationMinutes = HostIsolationExecutor.DefaultDurationMinutes;
            if (values.TryGetValue("durationMinutes", out var durElem) && durElem.ValueKind != JsonValueKind.Null)
            {
                if (!durElem.TryGetInt32(out durationMinutes))
                    return null;
            }

            bool lockWorkstation = false;
            if (values.TryGetValue("lockWorkstation", out var lockElem) && lockElem.ValueKind != JsonValueKind.Null)
            {
                if (lockElem.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    return null;
                lockWorkstation = lockElem.GetBoolean();
            }

            return new HostIsolationRequest(
                1,
                requestId,
                op.GetString()!,
                durationMinutes,
                lockWorkstation,
                Text("reason", 512),
                Text("consentToken", 64));
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
