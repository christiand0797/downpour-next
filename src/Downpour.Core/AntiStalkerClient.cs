using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>Desktop side of the read-only anti-stalker pipe. Returns null when the service is unreachable or replies invalidly.</summary>
public sealed class AntiStalkerClient(string pipeName = AntiStalkerClient.PipeName)
{
    public const string PipeName = "Downpour.AntiStalker.v1";

    public async Task<AntiStalkerSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeFramedAsync<AntiStalkerSnapshot>(pipe, timeout.Token);
            return IsValid(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonReaderException or JsonSerializationException)
        {
            return null;
        }
    }

    public static bool IsValid(AntiStalkerSnapshot? s) =>
        s is { SchemaVersion: 1 }
        && s.SensorUsage is { Count: <= 1000 } && s.RemoteSessions is { Count: <= 64 } && s.RemoteControl is { Count: <= 256 }
        && s.Monitoring is { Count: <= 64 } && s.Log is { Count: <= 500 } && s.Warnings is { Count: <= 64 }
        && s.SensorUsage.All(u => u is not null && WatchCapabilities.All.Contains(u.Capability) && Text(u.App, 260) && Text(u.DisplayName, 128))
        && s.RemoteSessions.All(r => r is not null && Text(r.State, 32) && Text(r.Protocol, 64) && (r.ClientName is null || Text(r.ClientName, 64)))
        && s.RemoteControl.All(r => r is not null && Text(r.ProcessName, 128) && Text(r.Product, 128) && Text(r.Category, 64))
        && s.Monitoring.All(m => m is not null && Text(m.Name, 256) && Text(m.Product, 128) && Text(m.Category, 64) && Text(m.Severity, 16) && Text(m.Source, 64))
        && s.Log.All(e => e is not null && Text(e.Kind, 64) && Text(e.Subject, 256) && Text(e.Detail, 512) && Text(e.Severity, 16))
        && s.Warnings.All(w => Text(w, 512));

    private static bool Text(string? value, int max) => value is not null && value.Length <= max && !value.Any(char.IsControl);
}
