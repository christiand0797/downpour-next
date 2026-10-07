using System.IO.Pipes;
using System.Net;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>
/// Handles firewall action requests (DN-008 Phase 3).
/// Enforces caller authentication, feature switches, single-use consent tokens, and audit logging.
/// </summary>
public sealed class FirewallActionHandler(
    FirewallActionExecutor executor,
    SensorSettingsStore settings,
    ActionConsentStore consent,
    ActionAuditLog audit)
{
    public async Task<FirewallActionResponse> HandleAsync(
        FirewallActionRequest request,
        string? callerDenial,
        CancellationToken token)
    {
        var enabled = settings.Current.FirewallActions;

        FirewallActionResponse Respond(
            bool accepted,
            string code,
            string message,
            IReadOnlyList<string>? rulesModified = null,
            FirewallActionPreview? preview = null,
            string? target = null)
        {
            audit.Record(request.Operation, code, target ?? request.TargetIp ?? request.RuleName, null);
            return new FirewallActionResponse(1, request.RequestId, accepted, code, message, enabled, rulesModified, preview);
        }

        if (callerDenial is not null)
            return Respond(false, "denied-caller", callerDenial);

        if (!enabled)
            return Respond(false, "disabled", "Firewall actions are turned off in Settings.");

        switch (request.Operation)
        {
            case FirewallActionOperations.PreviewBlockIp:
            {
                var (allowed, denyReason, ip) = executor.ValidateRemoteIp(request.TargetIp);
                if (!allowed || ip is null)
                {
                    var deniedPreview = new FirewallActionPreview(
                        request.Operation,
                        request.TargetIp,
                        null,
                        [],
                        request.DurationMinutes,
                        denyReason,
                        null,
                        null,
                        [],
                        []);
                    return Respond(false, "denied-protected-ip", denyReason ?? "Invalid IP address.", preview: deniedPreview, target: request.TargetIp);
                }

                // Bind the duration the user reviewed into the confirmation, so a different duration cannot reuse it.
                var (consentToken, expires) = consent.Mint(
                    FirewallActionOperations.BlockIp,
                    $"{ip}|{request.DurationMinutes}",
                    "Firewall Remote IP Block");

                var sanitized = ip.ToString().Replace(':', '_');
                var rulesAffected = new List<string>
                {
                    $"{FirewallActionExecutor.RulePrefix}{sanitized}_Out",
                    $"{FirewallActionExecutor.RulePrefix}{sanitized}_In"
                };

                var durationDesc = request.DurationMinutes > 0 ? $"{request.DurationMinutes} minutes" : "Permanent";
                var expectedEffects = new List<string>
                {
                    $"Create inbound and outbound Windows Firewall rules blocking remote IP '{ip}'",
                    "Drop all network packets to and from the target address across all network profiles",
                    $"Rule duration set to {durationDesc} with automatic expiration tracking",
                    "Record firewall modification event in the tamper-evident audit journal"
                };

                var risks = new List<string>
                {
                    "Any legitimate service, website, or API hosted at the target IP will become unreachable",
                    "If the target is a shared CDN or cloud provider, other co-hosted services may be affected",
                    "Active connections to the target IP will be interrupted"
                };

                var preview = new FirewallActionPreview(
                    request.Operation,
                    ip.ToString(),
                    null,
                    rulesAffected,
                    request.DurationMinutes,
                    null,
                    consentToken,
                    expires,
                    expectedEffects,
                    risks);

                return Respond(true, "preview", "Review IP block details and confirm action.", preview: preview, target: ip.ToString());
            }

            case FirewallActionOperations.BlockIp:
            {
                var (allowed, denyReason, ip) = executor.ValidateRemoteIp(request.TargetIp);
                if (!allowed || ip is null)
                {
                    return Respond(false, "denied-protected-ip", denyReason ?? "Invalid IP address.", target: request.TargetIp);
                }

                if (string.IsNullOrEmpty(request.ConsentToken) || !consent.TryConsume(request.ConsentToken, FirewallActionOperations.BlockIp, $"{ip}|{request.DurationMinutes}", out _))
                {
                    return Respond(false, "denied-consent", "The firewall action confirmation expired or did not match. Review the target IP again.", target: ip.ToString());
                }

                var (succeeded, createdRules, error) = executor.BlockRemoteIp(ip, request.DurationMinutes, request.Reason);
                if (!succeeded)
                {
                    return Respond(false, "error", error ?? "Failed to create firewall rules.", target: ip.ToString());
                }

                return Respond(true, "blocked", $"Successfully blocked remote IP {ip} ({string.Join(", ", createdRules)}).", rulesModified: createdRules, target: ip.ToString());
            }

            case FirewallActionOperations.PreviewRemoveRule:
            {
                var (allowed, denyReason) = executor.ValidateRuleNameForRemoval(request.RuleName);
                if (!allowed || string.IsNullOrWhiteSpace(request.RuleName))
                {
                    var deniedPreview = new FirewallActionPreview(
                        request.Operation,
                        null,
                        request.RuleName,
                        [],
                        0,
                        denyReason,
                        null,
                        null,
                        [],
                        []);
                    return Respond(false, "denied-protected-rule", denyReason ?? "Invalid rule name.", preview: deniedPreview, target: request.RuleName);
                }

                var ruleName = request.RuleName.Trim();
                var (consentToken, expires) = consent.Mint(
                    FirewallActionOperations.RemoveRule,
                    ruleName,
                    "Firewall Rule Removal");

                var expectedEffects = new List<string>
                {
                    $"Remove Windows Firewall rule '{ruleName}'",
                    "Restore standard network filtering behavior for matching network traffic",
                    "Record rule deletion in the append-only action audit log"
                };

                var risks = new List<string>
                {
                    "If the rule was actively blocking malicious traffic, that traffic will no longer be dropped"
                };

                var preview = new FirewallActionPreview(
                    request.Operation,
                    null,
                    ruleName,
                    [ruleName],
                    0,
                    null,
                    consentToken,
                    expires,
                    expectedEffects,
                    risks);

                return Respond(true, "preview", "Review rule removal details and confirm action.", preview: preview, target: ruleName);
            }

            case FirewallActionOperations.RemoveRule:
            {
                var (allowed, denyReason) = executor.ValidateRuleNameForRemoval(request.RuleName);
                if (!allowed || string.IsNullOrWhiteSpace(request.RuleName))
                {
                    return Respond(false, "denied-protected-rule", denyReason ?? "Invalid rule name.", target: request.RuleName);
                }

                var ruleName = request.RuleName.Trim();
                if (string.IsNullOrEmpty(request.ConsentToken) || !consent.TryConsume(request.ConsentToken, FirewallActionOperations.RemoveRule, ruleName, out _))
                {
                    return Respond(false, "denied-consent", "The rule removal confirmation expired or did not match. Review the rule again.", target: ruleName);
                }

                var (succeeded, error) = executor.RemoveRule(ruleName);
                if (!succeeded)
                {
                    return Respond(false, "error", error ?? "Failed to remove firewall rule.", target: ruleName);
                }

                return Respond(true, "removed", $"Successfully removed firewall rule '{ruleName}'.", rulesModified: [ruleName], target: ruleName);
            }

            case FirewallActionOperations.PreviewCleanupLegacy:
            {
                var (consentToken, expires) = consent.Mint(
                    FirewallActionOperations.CleanupLegacy,
                    "all-legacy-downpour-rules",
                    "Legacy Rule Cleanup");

                var expectedEffects = new List<string>
                {
                    "Identify and remove all leftover Windows Firewall rules created by legacy Downpour v29 (names starting with 'downpour')",
                    "Restore default Windows Firewall filtering policies for legacy blocked ports and services",
                    "Record legacy rule cleanup in the append-only action audit log"
                };

                var risks = new List<string>
                {
                    "Any custom blocks or port protections previously set in legacy v29 will be removed"
                };

                var preview = new FirewallActionPreview(
                    request.Operation,
                    null,
                    "all-legacy-downpour-rules",
                    ["All legacy 'downpour*' rules"],
                    0,
                    null,
                    consentToken,
                    expires,
                    expectedEffects,
                    risks);

                return Respond(true, "preview", "Review legacy rule cleanup details and confirm action.", preview: preview, target: "legacy-cleanup");
            }

            case FirewallActionOperations.CleanupLegacy:
            {
                if (string.IsNullOrEmpty(request.ConsentToken) || !consent.TryConsume(request.ConsentToken, FirewallActionOperations.CleanupLegacy, "all-legacy-downpour-rules", out _))
                {
                    return Respond(false, "denied-consent", "The legacy cleanup confirmation expired or did not match. Review the request again.", target: "legacy-cleanup");
                }

                var (succeeded, removedRules, error) = executor.CleanupLegacyRules();
                if (!succeeded)
                {
                    return Respond(false, "error", error ?? "Failed to clean up legacy rules.", rulesModified: removedRules, target: "legacy-cleanup");
                }

                return Respond(true, "cleaned-up", $"Successfully cleaned up {removedRules.Count} legacy Downpour rule(s).", rulesModified: removedRules, target: "legacy-cleanup");
            }

            default:
                return Respond(false, "invalid-request", "Unknown firewall action operation.");
        }
    }
}

/// <summary>
/// Named pipe service endpoint for Firewall actions (DN-008 Phase 3).
/// </summary>
public sealed class FirewallActionPipeWorker(
    FirewallActionHandler handler,
    FirewallActionExecutor executor,
    IActionCallerVerifier caller,
    ILogger<FirewallActionPipeWorker> logger,
    string pipeName = FirewallActionClient.PipeName) : BackgroundService
{
    public const int MaximumRequestBytes = 96 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 16 };
    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "requestId", "operation", "targetIp", "ruleName", "durationMinutes", "reason", "consentToken"
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Remove expired DownpourNext rules at startup and then every minute, so a timed block really ends on time
        // while the service runs (previously expiry was only enforced at the next service start).
        _ = Task.Run(async () =>
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var expired = executor.CleanupExpiredRules();
                    if (expired.Count > 0)
                        logger.LogInformation("Removed {Count} expired DownpourNext firewall rule(s).", expired.Count);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogDebug(ex, "Expired firewall rule cleanup encountered an error.");
                }
                try { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }, stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    4096,
                    4096,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());

                await pipe.WaitForConnectionAsync(stoppingToken);

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));

                var line = await ReadLineAsync(pipe, timeout.Token);
                var request = line is null ? null : ParseStrictRequest(line);

                FirewallActionResponse response;
                if (request is null)
                {
                    response = new FirewallActionResponse(1, Guid.Empty, false, "invalid-request", "The request was malformed.", false);
                }
                else
                {
                    using var actionTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    actionTimeout.CancelAfter(TimeSpan.FromSeconds(30));
                    response = await handler.HandleAsync(request, caller.Verify(pipe), actionTimeout.Token);
                }

                if (response.ResultCode is not "preview")
                {
                    logger.LogInformation("Firewall action request {Operation}: {ResultCode}.", request?.Operation ?? "invalid", response.ResultCode);
                }

                await JsonSerializer.SerializeAsync(pipe, response, JsonOptions, stoppingToken);
                await pipe.WriteAsync(new byte[] { (byte)'\n' }, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(ex, "A firewall action client disconnected before completion.");
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException && !stoppingToken.IsCancellationRequested)
            {
                // A BackgroundService failure stops the whole host; one bad reply must not take the sensor service down.
                logger.LogWarning(ex, "A firewall action reply could not be written.");
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

    internal static FirewallActionRequest? ParseStrictRequest(byte[] bytes)
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
                || !values.TryGetValue("operation", out var op) || op.ValueKind != JsonValueKind.String || !FirewallActionOperations.All.Contains(op.GetString()!))
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

            // Every block expires (SECURITY.md, DN-008): 1 minute to 7 days, default 24 hours. No permanent blocks.
            int duration = 1440;
            if (values.TryGetValue("durationMinutes", out var durElem) && durElem.ValueKind != JsonValueKind.Null)
            {
                if (!durElem.TryGetInt32(out duration) || duration < 1 || duration > FirewallActionExecutor.MaximumBlockMinutes)
                    return null;
            }

            return new FirewallActionRequest(
                1,
                requestId,
                op.GetString()!,
                Text("targetIp", 128),
                Text("ruleName", 256),
                duration,
                Text("reason", 512),
                Text("consentToken", 64));
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
