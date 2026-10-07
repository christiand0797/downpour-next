using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>
/// Handles process termination action requests (DN-008 Phase 2).
/// Enforces caller authentication, feature switches, single-use consent tokens, and audit logging.
/// </summary>
public sealed class ProcessTerminationActionHandler(
    ProcessTerminationExecutor executor,
    SensorSettingsStore settings,
    ActionConsentStore consent,
    ActionAuditLog audit)
{
    public async Task<ProcessTerminationResponse> HandleAsync(
        ProcessTerminationRequest request,
        string? callerDenial,
        CancellationToken token)
    {
        var enabled = settings.Current.ProcessTerminationActions;

        ProcessTerminationResponse Respond(
            bool accepted,
            string code,
            string message,
            ProcessTerminationPreview? preview = null,
            int? pid = null,
            string? name = null)
        {
            audit.Record(request.Operation, code, pid?.ToString() ?? request.ProcessId.ToString(), name);
            return new ProcessTerminationResponse(1, request.RequestId, accepted, code, message, enabled, preview);
        }

        if (callerDenial is not null)
            return Respond(false, "denied-caller", callerDenial);

        if (!enabled)
            return Respond(false, "disabled", "Process termination actions are turned off in Settings.");

        switch (request.Operation)
        {
            case ProcessTerminationOperations.Preview:
            {
                ProcessCandidate candidate;
                try
                {
                    candidate = executor.Inspect(request.ProcessId, request.StartTimeUtc);
                }
                catch (ProcessTerminationRejectedException ex)
                {
                    return Respond(false, ex.Code, ex.Message, pid: request.ProcessId);
                }

                if (candidate.DenyReason is not null)
                {
                    var deniedPreview = new ProcessTerminationPreview(
                        request.ProcessId,
                        candidate.ProcessName,
                        candidate.ImagePath,
                        candidate.StartTimeUtc,
                        request.AlertId,
                        candidate.DenyReason,
                        null,
                        null,
                        [],
                        []);
                    return Respond(false, "denied-protected-process", candidate.DenyReason, deniedPreview, request.ProcessId, candidate.ProcessName);
                }

                var (consentToken, expires) = consent.Mint(
                    ProcessTerminationOperations.Terminate,
                    $"{request.ProcessId}|{candidate.StartTimeUtc.UtcTicks}|{candidate.ImagePath}",
                    candidate.ProcessName);

                var expectedEffects = new List<string>
                {
                    $"Terminate running process '{candidate.ProcessName}' (PID {request.ProcessId})",
                    "Release allocated virtual memory and close open system handles",
                    "Record termination event in the tamper-evident audit journal"
                };

                var risks = new List<string>
                {
                    "Terminating a process abruptly will result in unsaved data loss in the target application",
                    "Terminating dependent background tasks may cause unexpected service errors until reboot or relaunch",
                    "Process termination is irreversible; the application must be manually restarted if needed"
                };

                var preview = new ProcessTerminationPreview(
                    request.ProcessId,
                    candidate.ProcessName,
                    candidate.ImagePath,
                    candidate.StartTimeUtc,
                    request.AlertId,
                    null,
                    consentToken,
                    expires,
                    expectedEffects,
                    risks);

                return Respond(true, "preview", "Review process details and confirm termination.", preview, request.ProcessId, candidate.ProcessName);
            }

            case ProcessTerminationOperations.Terminate:
            {
                ProcessCandidate candidate;
                try
                {
                    candidate = executor.Inspect(request.ProcessId, request.StartTimeUtc);
                }
                catch (ProcessTerminationRejectedException ex)
                {
                    return Respond(false, ex.Code, ex.Message, pid: request.ProcessId);
                }

                if (candidate.DenyReason is not null)
                {
                    return Respond(false, "denied-protected-process", candidate.DenyReason, pid: request.ProcessId, name: candidate.ProcessName);
                }

                var targetKey = $"{request.ProcessId}|{candidate.StartTimeUtc.UtcTicks}|{candidate.ImagePath}";
                if (string.IsNullOrEmpty(request.ConsentToken) || !consent.TryConsume(request.ConsentToken, ProcessTerminationOperations.Terminate, targetKey, out _))
                {
                    return Respond(false, "denied-consent", "The termination confirmation expired or did not match. Review the process again.", pid: request.ProcessId, name: candidate.ProcessName);
                }

                var outcome = await executor.TerminateAsync(request.ProcessId, request.StartTimeUtc, "Terminated by operator consent", token);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, pid: request.ProcessId, name: candidate.ProcessName);
            }

            default:
                return Respond(false, "invalid-request", "Unknown process termination operation.");
        }
    }
}

/// <summary>
/// Named pipe service endpoint for Process Termination actions.
/// </summary>
public sealed class ProcessTerminationActionPipeWorker(
    ProcessTerminationActionHandler handler,
    IActionCallerVerifier caller,
    ILogger<ProcessTerminationActionPipeWorker> logger,
    string pipeName = ProcessTerminationClient.PipeName) : BackgroundService
{
    public const int MaximumRequestBytes = 96 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 4 };
    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "requestId", "operation", "processId", "startTimeUtc", "alertId", "consentToken"
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
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

                ProcessTerminationResponse response;
                if (request is null)
                {
                    response = new ProcessTerminationResponse(1, Guid.Empty, false, "invalid-request", "The request was malformed.", false);
                }
                else
                {
                    using var actionTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    actionTimeout.CancelAfter(TimeSpan.FromSeconds(15));
                    response = await handler.HandleAsync(request, caller.Verify(pipe), actionTimeout.Token);
                }

                if (response.ResultCode is not "preview")
                {
                    logger.LogInformation("Process termination request {Operation}: {ResultCode}.", request?.Operation ?? "invalid", response.ResultCode);
                }

                await JsonSerializer.SerializeAsync(pipe, response, JsonOptions, stoppingToken);
                await pipe.WriteAsync(new byte[] { (byte)'\n' }, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A process termination client disconnected before completion.");
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

    internal static ProcessTerminationRequest? ParseStrictRequest(byte[] bytes)
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
                || !values.TryGetValue("operation", out var operation) || operation.ValueKind != JsonValueKind.String || !ProcessTerminationOperations.All.Contains(operation.GetString()!)
                || !values.TryGetValue("processId", out var pidElem) || !pidElem.TryGetInt32(out var processId) || processId < 0
                || !values.TryGetValue("startTimeUtc", out var startElem) || !startElem.TryGetDateTimeOffset(out var startTimeUtc))
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

            return new ProcessTerminationRequest(
                1,
                requestId,
                operation.GetString()!,
                processId,
                startTimeUtc,
                Text("alertId", 128),
                Text("consentToken", 64));
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
