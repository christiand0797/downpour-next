using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class RemoteAccessClient(string pipeName = RemoteAccessClient.PipeName)
{
    public const string PipeName = "Downpour.RemoteAccess.v1";
    private const int MaximumRows = 512;
    private const int MaximumText = 512;
    private static readonly HashSet<string> Risks = new(StringComparer.Ordinal) { "Critical", "High", "Medium", "Low" };
    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal) { "CRITICAL", "HIGH", "MEDIUM", "LOW" };

    public async Task<RemoteAccessSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<RemoteAccessSnapshot>(pipe, timeout.Token);
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

    public static bool IsValid(RemoteAccessSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.RdpPort is null or (> 0 and <= 65535)
        && snapshot.Exposures is { Count: <= MaximumRows }
        && snapshot.Tools is { Count: <= MaximumRows }
        && snapshot.Findings is { Count: <= MaximumRows }
        && snapshot.Warnings is { Count: <= 16 }
        && snapshot.Warnings.All(Text)
        && snapshot.Exposures.All(e => e is not null && RemoteAccessKinds.All.Contains(e.Kind) && Risks.Contains(e.Risk)
            && e.LocalPort is >= 0 and <= 65535 && Text(e.Vector) && Text(e.Description) && Text(e.RemoteEndpoint) && Text(e.ProcessName))
        && snapshot.Tools.All(t => t is not null && Text(t.ProcessName) && Text(t.Category))
        && snapshot.Findings.All(f => f is not null && Severities.Contains(f.Severity) && Text(f.Technique) && Text(f.Summary) && Text(f.Indicator));

    private static bool Text(string? value) => value is not null && value.Length <= MaximumText;
}
