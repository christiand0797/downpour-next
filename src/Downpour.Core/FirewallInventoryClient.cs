using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class FirewallInventoryClient(string pipeName = FirewallInventoryClient.PipeName)
{
    public const string PipeName = "Downpour.FirewallInventory.v1";
    private const int MaximumRules = 4096;
    private const int MaximumEvents = 100;
    private const int MaximumFindings = 256;
    private const int MaximumText = 512;
    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal) { "LOW", "MEDIUM", "HIGH", "CRITICAL" };

    public async Task<FirewallSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<FirewallSnapshot>(pipe, timeout.Token);
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

    public static bool IsValid(FirewallSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && Text(snapshot.ServiceState)
        && snapshot.Profiles is { Count: <= 3 }
        && snapshot.Rules is not null && snapshot.Rules.Count <= MaximumRules && snapshot.RuleCount >= snapshot.Rules.Count
        && snapshot.BlockedConnections is { Count: <= MaximumEvents }
        && snapshot.Findings is { Count: <= MaximumFindings }
        && snapshot.Warnings is { Count: <= 64 }
        && FirewallBlockedEventsStatuses.All.Contains(snapshot.BlockedEventsStatus)
        && snapshot.Warnings.All(Text)
        && snapshot.Profiles.All(p => p is not null && Text(p.Profile) && Text(p.DefaultInboundAction) && Text(p.DefaultOutboundAction))
        && snapshot.Rules.All(r => r is not null && Text(r.Name) && Text(r.Direction) && Text(r.Action) && Text(r.Protocol)
            && Text(r.LocalPorts) && Text(r.RemoteAddresses) && Text(r.Profiles) && Text(r.Application) && Text(r.Service) && Text(r.AppPackage) && Text(r.Grouping))
        && snapshot.BlockedConnections.All(e => e is not null && Text(e.Direction) && Text(e.Application) && Text(e.SourceAddress)
            && Text(e.DestinationAddress) && Text(e.DestinationPort) && Text(e.Protocol))
        && snapshot.Findings.All(f => f is not null && Severities.Contains(f.Severity) && Text(f.Technique) && Text(f.Summary) && Text(f.Indicator));

    // Findings embed a rule name in the summary, so allow twice the per-field bound.
    private static bool Text(string? value) => value is not null && value.Length <= MaximumText * 2;
}
