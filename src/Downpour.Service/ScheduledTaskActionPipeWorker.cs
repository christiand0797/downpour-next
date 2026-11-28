using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>
/// Handles scheduled-task state changes. Every request is caller-verified, feature-switch gated, path-policy
/// checked, consent-token gated and audited; previews mint the token and execution consumes it exactly once.
/// </summary>
public sealed class ScheduledTaskActionHandler(
    ScheduledTaskActionExecutor executor,
    SensorSettingsStore settings,
    ActionConsentStore consent,
    ActionAuditLog audit)
{
    public ScheduledTaskActionResponse Handle(ScheduledTaskActionRequest request, string? callerDenial)
    {
        var enabled = settings.Current.ScheduledTaskActions;

        ScheduledTaskActionResponse Respond(
            bool accepted,
            string code,
            string message,
            bool? taskEnabled = null,
            ScheduledTaskActionPreview? preview = null)
        {
            audit.Record(request.Operation, code, request.TaskPath, null);
            return new ScheduledTaskActionResponse(1, request.RequestId, accepted, code, message, enabled,
                request.TaskPath, taskEnabled, preview);
        }

        if (callerDenial is not null)
            return Respond(false, "denied-caller", callerDenial);

        if (!enabled)
            return Respond(false, "disabled", "Scheduled-task changes are turned off in Settings.");

        var taskPath = request.TaskPath;
        if (!ScheduledTaskActionExecutor.IsValidTaskPath(taskPath))
            return Respond(false, "invalid-task-path", "Task path is not a valid Task Scheduler path.");

        if (ScheduledTaskActionExecutor.ProtectedReason(taskPath!) is { } protection)
        {
            var deniedPreview = new ScheduledTaskActionPreview(request.Operation, taskPath!, null, protection,
                null, null, [], []);
            return Respond(false, "denied-protected-task", protection, preview: deniedPreview);
        }

        var kind = KindOf(request.Operation);
        if (kind is null)
            return Respond(false, "invalid-operation", "Operation is not allow-listed.");

        var isPreview = request.Operation.StartsWith("preview-", StringComparison.Ordinal);
        if (isPreview)
        {
            var (token, expires) = consent.Mint(ExecuteOperation(kind.Value), taskPath!, DisplayName(kind.Value));
            var preview = BuildPreview(kind.Value, taskPath!, token, expires);
            return Respond(true, "preview-generated", "Review the effects, then confirm to apply them.", preview: preview);
        }

        if (!consent.TryConsume(request.ConsentToken, request.Operation, taskPath!, out _))
            return Respond(false, "denied-consent", "Consent token is missing, expired, or does not match this task and action.");

        var outcome = kind.Value == ScheduledTaskActionKind.Delete
            ? executor.Delete(taskPath!)
            : executor.SetEnabled(taskPath!, kind.Value == ScheduledTaskActionKind.Enable);

        return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message,
            kind.Value == ScheduledTaskActionKind.Enable ? true : kind.Value == ScheduledTaskActionKind.Disable ? false : null);
    }

    private static ScheduledTaskActionPreview BuildPreview(
        ScheduledTaskActionKind kind,
        string taskPath,
        string token,
        DateTimeOffset expires)
    {
        var (effects, risks) = kind switch
        {
            ScheduledTaskActionKind.Enable => (
                new List<string>
                {
                    $"Task Scheduler marks '{taskPath}' as enabled",
                    "Its triggers can run the task again, including at the next scheduled time",
                    "Windows records the change in its own Task Scheduler operational log",
                },
                new List<string>
                {
                    "The task will run its configured action again, which may start a program or script",
                }),
            ScheduledTaskActionKind.Disable => (
                new List<string>
                {
                    $"Task Scheduler marks '{taskPath}' as disabled",
                    "The task stays registered with its triggers and actions but will not run them",
                    "Windows records the change in its own Task Scheduler operational log",
                },
                new List<string>
                {
                    "Anything that depends on this task (backup, update, maintenance, cleanup) stops running until it is enabled again",
                }),
            _ => (
                new List<string>
                {
                    $"Task Scheduler permanently removes '{taskPath}' and its triggers and actions",
                    "Windows records the removal in its own Task Scheduler operational log",
                },
                new List<string>
                {
                    "Deletion cannot be undone from Downpour; recreating the task requires its original definition",
                    "A program or workflow that depends on this task may stop working",
                }),
        };

        return new ScheduledTaskActionPreview($"preview-{kind.ToString().ToLowerInvariant()}-task", taskPath,
            kind == ScheduledTaskActionKind.Enable ? false : kind == ScheduledTaskActionKind.Disable ? true : null,
            null, token, expires, effects, risks);
    }

    private static ScheduledTaskActionKind? KindOf(string operation) => operation switch
    {
        ScheduledTaskActionOperations.PreviewEnable or ScheduledTaskActionOperations.Enable => ScheduledTaskActionKind.Enable,
        ScheduledTaskActionOperations.PreviewDisable or ScheduledTaskActionOperations.Disable => ScheduledTaskActionKind.Disable,
        ScheduledTaskActionOperations.PreviewDelete or ScheduledTaskActionOperations.Delete => ScheduledTaskActionKind.Delete,
        _ => null,
    };

    private static string ExecuteOperation(ScheduledTaskActionKind kind) => kind switch
    {
        ScheduledTaskActionKind.Enable => ScheduledTaskActionOperations.Enable,
        ScheduledTaskActionKind.Disable => ScheduledTaskActionOperations.Disable,
        _ => ScheduledTaskActionOperations.Delete,
    };

    private static string DisplayName(ScheduledTaskActionKind kind) => kind switch
    {
        ScheduledTaskActionKind.Enable => "Enable Scheduled Task",
        ScheduledTaskActionKind.Disable => "Disable Scheduled Task",
        _ => "Delete Scheduled Task",
    };
}

/// <summary>Named pipe worker for scheduled-task actions on 'Downpour.ScheduledTaskActions.v1'.</summary>
public sealed class ScheduledTaskActionPipeWorker(
    ScheduledTaskActionHandler handler,
    IActionCallerVerifier callerVerifier,
    ILogger<ScheduledTaskActionPipeWorker> logger,
    string pipeName = ScheduledTaskActionPipeWorker.PipeName) : BackgroundService
{
    public const string PipeName = "Downpour.ScheduledTaskActions.v1";
    private const int MaximumRequestBytes = 32 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "requestId", "operation", "taskPath", "consentToken",
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
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
                ScheduledTaskActionResponse response;

                if (requestBytes is null)
                {
                    response = new(1, Guid.Empty, false, "invalid-request", "Request body was empty or exceeded size limit.", false);
                }
                else
                {
                    var request = ParseStrictRequest(requestBytes);
                    response = request is null
                        ? new(1, Guid.Empty, false, "malformed-request", "Request failed schema or parameter validation.", false)
                        : handler.Handle(request, callerDenial);
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
                logger.LogDebug(ex, "A scheduled-task action client disconnected before completion.");
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException && !stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(ex, "A scheduled-task action reply could not be written.");
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

    internal static ScheduledTaskActionRequest? ParseStrictRequest(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumRequestBytes) return null;
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                MaxDepth = 4,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
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
                || !values.TryGetValue("operation", out var op) || op.ValueKind != JsonValueKind.String || !ScheduledTaskActionOperations.All.Contains(op.GetString()!))
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

            return new ScheduledTaskActionRequest(1, requestId, op.GetString()!, Text("taskPath", 512),
                Text("consentToken", 64));
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
