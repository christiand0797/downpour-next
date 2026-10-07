using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class DnsInventoryClient(string pipeName = DnsInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.DnsInventory.v1";
    private const int MaximumEntries = 4096;
    private const int MaximumFindings = 256;
    private const int MaximumText = 512;
    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal) { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

    public async Task<DnsCacheSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeFramedAsync<DnsCacheSnapshot>(pipe, timeout.Token);
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

    public static bool IsValid(DnsCacheSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.TotalEntries >= 0
        && snapshot.HighRiskCount >= 0
        && snapshot.MediumRiskCount >= 0
        && snapshot.Entries is { Count: <= MaximumEntries }
        && snapshot.Findings is { Count: <= MaximumFindings }
        && snapshot.Warnings is { Count: <= 64 }
        && snapshot.Entries.All(e => e is not null && Text(e.Domain) && e.RiskScore >= 0 && e.RiskScore <= 100 && e.Factors.All(Text))
        && snapshot.Findings.All(f => f is not null && Severities.Contains(f.Severity) && Text(f.Technique) && Text(f.Summary) && Text(f.Indicator))
        && snapshot.Warnings.All(Text);

    private static bool Text(string? value) => value is not null && value.Length <= MaximumText * 2;
}
