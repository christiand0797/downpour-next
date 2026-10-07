using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class IntelClient(string pipeName = IntelClient.PipeName)
{
    public const string PipeName = "Downpour.Intel.v1";
    public const int MaximumResults = 500;
    public const int MaximumLog = 100;

    public async Task<IntelSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<IntelSnapshot>(pipe, timeout.Token);
            return IsValid(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonReaderException or JsonSerializationException)
        {
            return null;
        }
    }

    public static bool IsValid(IntelSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.ConfiguredServices is { Count: <= 8 } && snapshot.ConfiguredServices.All(IntelServices.All.Contains)
        && snapshot.LastRunStatus is { Length: <= 256 }
        && snapshot.Results is { Count: <= MaximumResults }
        && snapshot.RecentLookups is { Count: <= MaximumLog }
        && snapshot.Warnings is { Count: <= 16 }
        && snapshot.Results.All(r => r is not null && IntelServices.All.Contains(r.Service) && IntelKinds.All.Contains(r.IndicatorKind)
            && IntelVerdicts.All.Contains(r.Verdict) && r.Indicator is { Length: > 0 and <= 256 } && r.Summary is { Length: <= 256 })
        && snapshot.RecentLookups.All(l => l is not null && IntelServices.All.Contains(l.Service) && IntelKinds.All.Contains(l.IndicatorKind)
            && l.Outcome is { Length: <= 64 });
}
