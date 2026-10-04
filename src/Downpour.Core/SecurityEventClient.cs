using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class SecurityEventClient(string pipeName = SecurityEventClient.PipeName)
{
    public const string PipeName = "Downpour.SecurityEvents.v1";
    private readonly string _pipeName = pipeName;

    public async Task<SecurityEventSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<SecurityEventSnapshot>(pipe, timeout.Token);
            return snapshot is not null && IsValidSnapshot(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (JsonReaderException) { return null; }
        catch (JsonSerializationException) { return null; }
        catch (InvalidDataException) { return null; }
    }

    public static bool IsValidSnapshot(SecurityEventSnapshot snapshot)
    {
        if (snapshot.SchemaVersion != 1 || snapshot.SourcesQueried is < 0 or > 7 ||
            snapshot.Events is not { Count: <= 256 } || snapshot.Warnings is not { Count: <= 64 } ||
            snapshot.CapturedAtUtc < DateTimeOffset.UtcNow.AddMinutes(-10) || snapshot.CapturedAtUtc > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            return false;
        }

        var recordKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in snapshot.Events)
        {
            if (item is null || item.LogName is null || item.Provider is null || item.Severity is null || item.Technique is null || item.Summary is null ||
                item.LogName.Length > 128 || item.Provider.Length is 0 or > 128 || item.Severity.Length > 16 || item.Technique.Length > 32 || item.Summary.Length > 160 ||
                ContainsControl(item.LogName) || ContainsControl(item.Provider) || ContainsControl(item.Severity) || ContainsControl(item.Technique) || ContainsControl(item.Summary) ||
                item.EventId is < 0 or > ushort.MaxValue || item.RecordId is < 0 ||
                (item.EventId == 4625 ? item.Occurrences is < 10 or > 100 : item.Occurrences != 1) ||
                item.CreatedAtUtc is not { } eventTime || eventTime.Offset != TimeSpan.Zero ||
                eventTime > snapshot.CapturedAtUtc + TimeSpan.FromMinutes(1) || eventTime < snapshot.CapturedAtUtc.Subtract(TimeSpan.FromDays(1)).Subtract(TimeSpan.FromMinutes(10)) ||
                !SecurityEventCatalog.TryGetRule(item.LogName, item.EventId, out var rule) ||
                !item.Severity.Equals(rule.Severity, StringComparison.Ordinal) ||
                !item.Technique.Equals(rule.Technique, StringComparison.Ordinal) ||
                !item.Summary.Equals(rule.Summary, StringComparison.Ordinal))
            {
                return false;
            }

            if (item.RecordId is { } recordId && !recordKeys.Add($"{item.LogName}\0{recordId}")) return false;
        }

        return snapshot.Warnings.All(warning => warning is not null && warning.Length <= 512 && !ContainsControl(warning));
    }

    private static bool ContainsControl(string value) => value.Any(char.IsControl);
}
