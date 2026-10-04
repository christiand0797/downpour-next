using System.IO.Pipes;
using Newtonsoft.Json;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed class SystemSnapshotClient
{
    public const string PipeName = "Downpour.SystemSnapshot.v1";
    private readonly string _pipeName;

    public SystemSnapshotClient(string pipeName = PipeName) => _pipeName = pipeName;

    public async Task<SystemHealthSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<SystemHealthSnapshot>(pipe, timeout.Token);
            return snapshot is not null && IsValidSnapshot(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (JsonReaderException)
        {
            return null;
        }
        catch (JsonSerializationException)
        {
            return null;
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    public static bool IsValidSnapshot(SystemHealthSnapshot snapshot) =>
        snapshot.SchemaVersion == 1 && snapshot.CapturedAtUtc >= DateTimeOffset.UtcNow.AddMinutes(-10) &&
        snapshot.CapturedAtUtc <= DateTimeOffset.UtcNow.AddMinutes(1) && snapshot.ProcessCount >= 0 &&
        snapshot.CpuPercent is null or (>= 0 and <= 100) &&
        snapshot.MemoryAvailableBytes <= snapshot.MemoryTotalBytes &&
        snapshot.ActiveTcpConnections is null or >= 0 &&
        snapshot.TopProcesses is { Count: <= 512 } && snapshot.ProcessCount >= snapshot.TopProcesses.Count && snapshot.Warnings is { Count: <= 64 } &&
        snapshot.TopProcesses.All(process => process is not null && process.ProcessId > 0 && process.Name is { Length: > 0 and <= 128 } && !process.Name.Any(char.IsControl) &&
            process.WorkingSetBytes >= 0 && process.ThreadCount >= 0) &&
        snapshot.Warnings.All(warning => warning is not null && warning.Length <= 512);
}
