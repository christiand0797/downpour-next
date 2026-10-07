using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Client for the USB Device Action endpoint (DN-008 Phase 4).
/// Connects to the local service's action pipe to request operator preview and confirmed execution
/// of USB device blocking/unblocking and USBSTOR mass storage driver configuration.
/// </summary>
public sealed class UsbActionClient(string pipeName = UsbActionClient.PipeName)
{
    public const string PipeName = "Downpour.UsbActions.v1";
    private const int MaximumResponseBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public Task<UsbActionResponse?> PreviewBlockDeviceAsync(
        string deviceId,
        string? friendlyName = null,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new UsbActionRequest(
            1,
            Guid.NewGuid(),
            UsbActionOperations.PreviewBlockDevice,
            DeviceId: deviceId,
            FriendlyName: friendlyName,
            Reason: reason),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<UsbActionResponse?> BlockDeviceAsync(
        string deviceId,
        string consentToken,
        string? friendlyName = null,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new UsbActionRequest(
            1,
            Guid.NewGuid(),
            UsbActionOperations.BlockDevice,
            DeviceId: deviceId,
            FriendlyName: friendlyName,
            Reason: reason,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    public Task<UsbActionResponse?> PreviewUnblockDeviceAsync(
        string deviceId,
        string? friendlyName = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new UsbActionRequest(
            1,
            Guid.NewGuid(),
            UsbActionOperations.PreviewUnblockDevice,
            DeviceId: deviceId,
            FriendlyName: friendlyName),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<UsbActionResponse?> UnblockDeviceAsync(
        string deviceId,
        string consentToken,
        string? friendlyName = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new UsbActionRequest(
            1,
            Guid.NewGuid(),
            UsbActionOperations.UnblockDevice,
            DeviceId: deviceId,
            FriendlyName: friendlyName,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    public Task<UsbActionResponse?> PreviewSetUsbStorageAsync(
        bool enabled,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new UsbActionRequest(
            1,
            Guid.NewGuid(),
            UsbActionOperations.PreviewSetUsbStorage,
            UsbStorageEnabled: enabled,
            Reason: reason),
            TimeSpan.FromSeconds(10),
            cancellationToken);

    public Task<UsbActionResponse?> SetUsbStorageAsync(
        bool enabled,
        string consentToken,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        SendAsync(new UsbActionRequest(
            1,
            Guid.NewGuid(),
            UsbActionOperations.SetUsbStorage,
            UsbStorageEnabled: enabled,
            Reason: reason,
            ConsentToken: consentToken),
            TimeSpan.FromSeconds(15),
            cancellationToken);

    private async Task<UsbActionResponse?> SendAsync(
        UsbActionRequest request,
        TimeSpan deadline,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = new CancellationTokenSource(deadline);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, cancellationToken);

        try
        {
            using var client = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await client.ConnectAsync(linkedCts.Token);

            var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, Json);
            await client.WriteAsync(requestBytes, linkedCts.Token);
            client.WriteByte((byte)'\n');
            await client.FlushAsync(linkedCts.Token);

            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            while (buffer.Length <= MaximumResponseBytes)
            {
                var read = await client.ReadAsync(chunk, linkedCts.Token);
                if (read == 0) break;
                var newline = Array.IndexOf(chunk, (byte)'\n', 0, read);
                if (newline >= 0)
                {
                    buffer.Write(chunk, 0, newline);
                    break;
                }
                buffer.Write(chunk, 0, read);
            }

            if (buffer.Length == 0) return null;
            return JsonSerializer.Deserialize<UsbActionResponse>(buffer.ToArray(), Json);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
