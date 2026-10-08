using System.Buffers.Binary;
using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>Desktop side of the Devices &amp; Drivers pipe. Returns null when the service is unreachable or replies invalidly.</summary>
public sealed class DeviceClient(string pipeName = DeviceClient.PipeName)
{
    public const string PipeName = "Downpour.Devices.v1";

    public string? LastFailure { get; private set; }

    public Task<DeviceResponse?> GetSnapshotAsync(CancellationToken token = default) => SendAsync(DeviceOperations.Snapshot, token);

    public Task<DeviceResponse?> SearchUpdatesAsync(CancellationToken token = default) => SendAsync(DeviceOperations.SearchUpdates, token);

    private async Task<DeviceResponse?> SendAsync(string operation, CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(45)); // the first device inventory can take a while on large PCs
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var body = BoundedJson.Serialize(new DeviceRequest(1, operation));
            var length = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(length, body.Length);
            await pipe.WriteAsync(length, timeout.Token);
            await pipe.WriteAsync(body, timeout.Token);
            await pipe.FlushAsync(timeout.Token);
            var response = await BoundedJson.DeserializeFramedAsync<DeviceResponse>(pipe, timeout.Token);
            if (!IsValid(response))
            {
                LastFailure = "The sensor service replied, but its device list did not pass validation.";
                return null;
            }
            LastFailure = null;
            return response;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            LastFailure = "The sensor service did not answer in time; it may still be reading the device list.";
            return null;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonReaderException or JsonSerializationException or EndOfStreamException)
        {
            LastFailure = $"The connection to the sensor service failed ({ex.GetType().Name}).";
            return null;
        }
    }

    public static bool IsValid(DeviceResponse? r) =>
        r is { SchemaVersion: 1 } && Text(r.ResultCode, 32) && (r.Snapshot is null || IsValid(r.Snapshot));

    public static bool IsValid(DeviceInventorySnapshot s) =>
        s is { SchemaVersion: 1 } && s.Devices is { Count: <= 1200 } && s.Updates is { Count: <= 200 } && s.Warnings is { Count: <= 16 }
        && Text(s.UpdateSearchState, 16) && (s.UpdateSearchError is null || Text(s.UpdateSearchError, 300))
        && s.Devices.All(d => d is not null && Text(d.InstanceId, 400) && Text(d.Name, 200) && Text(d.Class, 64) && Text(d.Manufacturer, 128, allowEmpty: true)
            && Text(d.Status, 32) && d.ProblemCode is >= 0 and <= 999 && Optional(d.DriverProvider, 128) && Optional(d.DriverVersion, 64)
            && Optional(d.InfName, 128) && Optional(d.DriverSigner, 200) && Optional(d.HardwareId, 256))
        && s.Updates.All(u => u is not null && Text(u.Title, 300) && Optional(u.DriverClass, 64) && Optional(u.DriverModel, 200)
            && Optional(u.DriverProvider, 128) && Optional(u.DriverManufacturer, 128) && Optional(u.DriverHardwareId, 256) && u.MaximumDownloadBytes is null or >= 0)
        && s.Warnings.All(w => Text(w, 300))
        && Optional(s.SystemManufacturer, 128) && Optional(s.SystemModel, 128) && Optional(s.BoardManufacturer, 128) && Optional(s.BoardProduct, 128)
        && (s.VendorTools is null || s.VendorTools.Count <= 32 && s.VendorTools.All(t => Text(t, 64)));

    private static bool Optional(string? value, int max) => value is null || Text(value, max);

    private static bool Text(string? value, int max, bool allowEmpty = false) =>
        value is not null && (allowEmpty || value.Length > 0) && value.Length <= max && !value.Any(char.IsControl);
}
