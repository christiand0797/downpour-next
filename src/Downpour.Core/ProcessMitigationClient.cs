using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class ProcessMitigationClient(string pipeName = ProcessMitigationClient.PipeName)
{
    public const string PipeName = "Downpour.ProcessMitigations.v1";

    public async Task<ProcessMitigationSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            // Opening a few hundred processes is bounded by the provider, not by this timeout.
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);

            var snapshot = await BoundedJson.DeserializeAsync<ProcessMitigationSnapshot>(pipe, timeout.Token);
            return IsValid(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
            or JsonReaderException or JsonSerializationException)
        {
            return null;
        }
    }

    public static bool IsValid(ProcessMitigationSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.Processes is not null
        && snapshot.Warnings is not null
        && snapshot.Processes.Count <= ProcessMitigationLimits.MaximumProcesses
        && snapshot.Warnings.Count <= ProcessMitigationLimits.MaximumWarnings
        && snapshot.RefusedCount is >= 0 and <= ProcessMitigationLimits.MaximumRefused
        && snapshot.CapturedAtUtc > DateTimeOffset.UnixEpoch
        && snapshot.CapturedAtUtc <= DateTimeOffset.UtcNow.AddDays(2)
        && snapshot.Warnings.All(warning => warning is not null && warning.Length <= 512)
        && snapshot.Processes.All(entry => entry is not null
            && !string.IsNullOrWhiteSpace(entry.ProcessName)
            && entry.ProcessName.Length <= ProcessMitigationLimits.MaximumNameLength
            && entry.ProcessId > 0
            && entry.InstanceCount is >= 1 and <= ProcessMitigationLimits.MaximumInstances);
}
