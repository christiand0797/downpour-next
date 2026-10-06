using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed class DriverPackageInventoryClient : IDisposable
{
    private const string PipeName = "downpour.driver-package-inventory";
    private readonly TimeSpan _connectTimeout = TimeSpan.FromSeconds(5);
    private readonly TimeSpan _readTimeout = TimeSpan.FromSeconds(10);

    public async Task<DriverPackageInventorySnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(_connectTimeout, cancellationToken);

            client.ReadTimeout = (int)_readTimeout.TotalMilliseconds;

            var lengthBytes = new byte[4];
            await client.ReadExactlyAsync(lengthBytes, cancellationToken);
            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);

            if (length > 4 * 1024 * 1024) // 4 MiB cap
                throw new InvalidDataException("Driver package inventory payload exceeds size limit.");

            var payload = new byte[length];
            await client.ReadExactlyAsync(payload, cancellationToken);

            return BoundedJson.Deserialize<DriverPackageInventorySnapshot>(payload);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or OperationCanceledException)
        {
            return null;
        }
    }

    public void Dispose() { }
}