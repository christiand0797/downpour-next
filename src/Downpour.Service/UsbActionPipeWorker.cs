using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>
/// Handles USB device action requests (DN-008 Phase 4).
/// Enforces caller authentication, feature switches, single-use consent tokens, and audit logging.
/// </summary>
public sealed class UsbActionHandler(
    UsbActionExecutor executor,
    SensorSettingsStore settings,
    ActionConsentStore consent,
    ActionAuditLog audit)
{
    public async Task<UsbActionResponse> HandleAsync(
        UsbActionRequest request,
        string? callerDenial,
        CancellationToken token)
    {
        var enabled = settings.Current.UsbActions;

        UsbActionResponse Respond(
            bool accepted,
            string code,
            string message,
            string? deviceId = null,
            bool? usbStorageEnabled = null,
            UsbActionPreview? preview = null)
        {
            audit.Record(request.Operation, code, deviceId ?? request.DeviceId, request.FriendlyName);
            return new UsbActionResponse(1, request.RequestId, accepted, code, message, enabled, deviceId, usbStorageEnabled, preview);
        }

        if (callerDenial is not null)
            return Respond(false, "denied-caller", callerDenial);

        if (!enabled)
            return Respond(false, "disabled", "USB actions are turned off in Settings.");

        switch (request.Operation)
        {
            case UsbActionOperations.PreviewBlockDevice:
            {
                if (string.IsNullOrWhiteSpace(request.DeviceId))
                    return Respond(false, "invalid-device-id", "Device ID is required.");

                var (allowed, denyReason) = executor.ValidateDevice(request.DeviceId, request.FriendlyName);
                if (!allowed)
                {
                    var deniedPreview = new UsbActionPreview(
                        request.Operation,
                        request.DeviceId,
                        request.FriendlyName,
                        executor.GetUsbStorageEnabled(),
                        denyReason,
                        null,
                        null,
                        [],
                        []);
                    return Respond(false, "denied-protected-device", denyReason ?? "Device is protected.", preview: deniedPreview, deviceId: request.DeviceId);
                }

                var (consentToken, expires) = consent.Mint(
                    UsbActionOperations.BlockDevice,
                    request.DeviceId.Trim(),
                    "USB Device Block");

                var expectedEffects = new List<string>
                {
                    $"Disable Windows PnP device node for USB device '{request.DeviceId}'",
                    "Add device identifier to Downpour persistent blocked device store",
                    "Prevent device from functioning until explicitly unblocked by an operator",
                    "Record device blocking event in the tamper-evident audit journal"
                };

                var risks = new List<string>
                {
                    "The device will immediately stop responding and become unusable",
                    "Any pending I/O or unsaved data transfers to the device will fail"
                };

                var preview = new UsbActionPreview(
                    request.Operation,
                    request.DeviceId.Trim(),
                    request.FriendlyName,
                    executor.GetUsbStorageEnabled(),
                    null,
                    consentToken,
                    expires,
                    expectedEffects,
                    risks);

                return Respond(true, "preview-generated", "Consent token minted. Action preview ready for operator confirmation.", preview: preview, deviceId: request.DeviceId);
            }

            case UsbActionOperations.BlockDevice:
            {
                if (string.IsNullOrWhiteSpace(request.DeviceId))
                    return Respond(false, "invalid-device-id", "Device ID is required.");

                if (!consent.TryConsume(request.ConsentToken, UsbActionOperations.BlockDevice, request.DeviceId.Trim(), out _))
                {
                    return Respond(false, "denied-consent", "Consent token is missing, expired, or does not match this operation and device ID.", deviceId: request.DeviceId);
                }

                var outcome = executor.BlockDevice(request.DeviceId, request.FriendlyName, request.Reason);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, deviceId: request.DeviceId);
            }

            case UsbActionOperations.PreviewUnblockDevice:
            {
                if (string.IsNullOrWhiteSpace(request.DeviceId))
                    return Respond(false, "invalid-device-id", "Device ID is required.");

                var (consentToken, expires) = consent.Mint(
                    UsbActionOperations.UnblockDevice,
                    request.DeviceId.Trim(),
                    "USB Device Unblock");

                var expectedEffects = new List<string>
                {
                    $"Re-enable Windows PnP device node for USB device '{request.DeviceId}'",
                    "Remove device identifier from Downpour persistent blocked device store",
                    "Allow Windows to initialize and communicate with the device",
                    "Record device unblocking event in the tamper-evident audit journal"
                };

                var risks = new List<string>
                {
                    "If the device is malicious (e.g. BadUSB/Rubber Ducky/infected media), it may execute unauthorized payloads upon activation"
                };

                var preview = new UsbActionPreview(
                    request.Operation,
                    request.DeviceId.Trim(),
                    request.FriendlyName,
                    executor.GetUsbStorageEnabled(),
                    null,
                    consentToken,
                    expires,
                    expectedEffects,
                    risks);

                return Respond(true, "preview-generated", "Consent token minted. Action preview ready for operator confirmation.", preview: preview, deviceId: request.DeviceId);
            }

            case UsbActionOperations.UnblockDevice:
            {
                if (string.IsNullOrWhiteSpace(request.DeviceId))
                    return Respond(false, "invalid-device-id", "Device ID is required.");

                if (!consent.TryConsume(request.ConsentToken, UsbActionOperations.UnblockDevice, request.DeviceId.Trim(), out _))
                {
                    return Respond(false, "denied-consent", "Consent token is missing, expired, or does not match this operation and device ID.", deviceId: request.DeviceId);
                }

                var outcome = executor.UnblockDevice(request.DeviceId, request.FriendlyName);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, deviceId: request.DeviceId);
            }

            case UsbActionOperations.PreviewSetUsbStorage:
            {
                var targetKey = $"set-usbstorage|{request.UsbStorageEnabled}";
                var (consentToken, expires) = consent.Mint(
                    UsbActionOperations.SetUsbStorage,
                    targetKey,
                    "USB Storage Toggle");

                var expectedEffects = new List<string>
                {
                    $"Configure Windows USBSTOR storage driver start state to {(request.UsbStorageEnabled ? "Demand Start (Enabled)" : "Disabled (4)")}",
                    request.UsbStorageEnabled
                        ? "Newly inserted USB mass storage devices will be recognized and mounted by Windows"
                        : "Newly inserted USB mass storage devices will be prevented from mounting",
                    "Record USB storage policy update in the tamper-evident audit journal"
                };

                var risks = new List<string>
                {
                    request.UsbStorageEnabled
                        ? "Untrusted USB flash drives or external storage can mount and transfer files"
                        : "Legitimate external USB drives cannot be accessed until mass storage is re-enabled"
                };

                var preview = new UsbActionPreview(
                    request.Operation,
                    null,
                    null,
                    request.UsbStorageEnabled,
                    null,
                    consentToken,
                    expires,
                    expectedEffects,
                    risks);

                return Respond(true, "preview-generated", "Consent token minted. Action preview ready for operator confirmation.", preview: preview, usbStorageEnabled: request.UsbStorageEnabled);
            }

            case UsbActionOperations.SetUsbStorage:
            {
                var targetKey = $"set-usbstorage|{request.UsbStorageEnabled}";
                if (!consent.TryConsume(request.ConsentToken, UsbActionOperations.SetUsbStorage, targetKey, out _))
                {
                    return Respond(false, "denied-consent", "Consent token is missing, expired, or does not match this operation.", usbStorageEnabled: request.UsbStorageEnabled);
                }

                var outcome = executor.SetUsbStorage(request.UsbStorageEnabled, request.Reason);
                return Respond(outcome.Succeeded, outcome.ResultCode, outcome.Message, usbStorageEnabled: request.UsbStorageEnabled);
            }

            default:
                return Respond(false, "invalid-operation", $"Unknown operation '{request.Operation}'.");
        }
    }
}

/// <summary>
/// Named pipe worker for USB device action requests on 'Downpour.UsbActions.v1'.
/// </summary>
public sealed class UsbActionPipeWorker(
    UsbActionHandler handler,
    IActionCallerVerifier callerVerifier,
    ILogger<UsbActionPipeWorker> logger) : BackgroundService
{
    public const string PipeName = "Downpour.UsbActions.v1";
    private const int MaximumRequestBytes = 32 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion", "requestId", "operation", "deviceId", "friendlyName", "usbStorageEnabled", "reason", "consentToken"
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
                UsbActionResponse response;

                if (requestBytes is null)
                {
                    response = new UsbActionResponse(1, Guid.Empty, false, "invalid-request", "Request body was empty or exceeded size limit.", false);
                }
                else
                {
                    var request = ParseStrictRequest(requestBytes);
                    if (request is null)
                    {
                        response = new UsbActionResponse(1, Guid.Empty, false, "malformed-request", "Request failed schema or parameter validation.", false);
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
                logger.LogDebug(ex, "A USB action client disconnected before completion.");
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException && !stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(ex, "A USB action reply could not be written.");
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

    internal static UsbActionRequest? ParseStrictRequest(byte[] bytes)
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
                || !values.TryGetValue("operation", out var op) || op.ValueKind != JsonValueKind.String || !UsbActionOperations.All.Contains(op.GetString()!))
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

            bool usbStorageEnabled = true;
            if (values.TryGetValue("usbStorageEnabled", out var storageElem) && storageElem.ValueKind != JsonValueKind.Null)
            {
                if (storageElem.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    return null;
                usbStorageEnabled = storageElem.GetBoolean();
            }

            return new UsbActionRequest(
                1,
                requestId,
                op.GetString()!,
                Text("deviceId", 256),
                Text("friendlyName", 256),
                usbStorageEnabled,
                Text("reason", 512),
                Text("consentToken", 64));
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
