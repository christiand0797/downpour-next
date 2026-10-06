using System.Buffers.Binary;
using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class DriverPackageInventoryClient(string pipeName = DriverPackageInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.DriverPackageInventory.v1";
    private const int MaximumPayloadBytes = 4 * 1024 * 1024;
    private const int MaximumRows = 1024;
    private const int MaximumTextLength = 1024;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    // Allows for a cold capture that catalog-verifies every package.
    private static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(45);

    public async Task<DriverPackageInventorySnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TotalTimeout);
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(ConnectTimeout, timeout.Token);

            var lengthBytes = new byte[4];
            await pipe.ReadExactlyAsync(lengthBytes, timeout.Token);
            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length is <= 0 or > MaximumPayloadBytes) return null;

            var payload = new byte[length];
            await pipe.ReadExactlyAsync(payload, timeout.Token);
            var snapshot = BoundedJson.Deserialize<DriverPackageInventorySnapshot>(payload);
            return IsValid(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TimeoutException
            or InvalidDataException or JsonReaderException or JsonSerializationException)
        {
            return null;
        }
    }

    internal static bool IsValid(DriverPackageInventorySnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.Packages is not null
        && snapshot.Warnings is not null
        && snapshot.PackageCount == snapshot.Packages.Count
        && snapshot.Packages.Count <= MaximumRows
        && snapshot.Warnings.Count <= 64
        && snapshot.Warnings.All(warning => warning is not null && warning.Length <= 512)
        && snapshot.Packages.All(package => package is not null
            && Bounded(package.InfFile) && Bounded(package.OriginalInfFile) && Bounded(package.DriverClass)
            && Bounded(package.ProviderName) && Bounded(package.DriverVersion) && Bounded(package.Date)
            && Bounded(package.HardwareId) && BoundedOrNull(package.SignerName) && BoundedOrNull(package.SignatureStatus));

    private static bool Bounded(string? value) => value is not null && value.Length <= MaximumTextLength;
    private static bool BoundedOrNull(string? value) => value is null || value.Length <= MaximumTextLength;
}
