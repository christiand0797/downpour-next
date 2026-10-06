using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class PersistenceInventoryClient(string pipeName = PersistenceInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.PersistenceInventory.v1";
    private const int MaximumEntries = 4096;
    private const int MaximumText = 1024;
    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal) { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

    public async Task<PersistenceSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            // Task Scheduler and WMI enumeration can take several seconds on a cold capture.
            timeout.CancelAfter(TimeSpan.FromSeconds(45));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<PersistenceSnapshot>(pipe, timeout.Token);
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

    public static bool IsValid(PersistenceSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.Entries is { Count: <= MaximumEntries }
        && snapshot.Findings is { Count: <= 256 }
        && snapshot.SourceStatus is { Count: <= 32 }
        && snapshot.Warnings is { Count: <= 32 }
        && snapshot.SourceStatus.All(Text) && snapshot.Warnings.All(Text)
        && snapshot.Entries.All(e => e is not null && PersistenceCategories.All.Contains(e.Category) && PersistenceChanges.All.Contains(e.Change)
            && Text(e.Location) && Text(e.Name) && Text(e.Value) && Text(e.Technique)
            && e.Indicators is { Count: <= 8 } && e.Indicators.All(Text))
        && snapshot.Findings.All(f => f is not null && Severities.Contains(f.Severity) && PersistenceCategories.All.Contains(f.Category)
            && Text(f.Technique) && Text(f.Summary) && Text(f.Indicator));

    private static bool Text(string? value) => value is not null && value.Length <= MaximumText;
}
