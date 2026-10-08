using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>Desktop side of the read-only Audio Shield pipe. Returns null when the service is unreachable or replies invalidly.</summary>
public sealed class AudioClient(string pipeName = AudioClient.PipeName)
{
    public const string PipeName = "Downpour.Audio.v1";

    private static readonly HashSet<string> Severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", AudioThreatAnalyzer.Info];
    private static readonly HashSet<string> Categories =
        [AudioIssueCategories.Listening, AudioIssueCategories.Device, AudioIssueCategories.Driver, AudioIssueCategories.Glitch, AudioIssueCategories.Privacy];
    private static readonly HashSet<string> Flows = [AudioFlows.Playback, AudioFlows.Recording];

    public async Task<AudioSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeFramedAsync<AudioSnapshot>(pipe, timeout.Token);
            return IsValid(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonReaderException or JsonSerializationException)
        {
            return null;
        }
    }

    public static bool IsValid(AudioSnapshot? s) =>
        s is { SchemaVersion: 1, Posture: not null }
        && s.Devices is { Count: <= AudioThreatAnalyzer.MaximumDevices } && s.Sessions is { Count: <= AudioThreatAnalyzer.MaximumSessions }
        && s.Effects is { Count: <= AudioThreatAnalyzer.MaximumEffects } && s.Issues is { Count: <= 128 } && s.Warnings is { Count: <= 64 }
        && s.Devices.All(d => d is not null && Text(d.Id, 512) && Text(d.Name, 256) && Text(d.Adapter, 256) && Flows.Contains(d.Flow)
            && Text(d.State, 32) && Text(d.Kind, 32) && (d.Format is null || Text(d.Format, 64)) && d.VolumePercent is null or (>= 0 and <= 100)
            && Level(d.Peak))
        && s.Sessions.All(x => x is not null && Flows.Contains(x.Flow) && Text(x.Device, 256) && Text(x.DeviceKind, 32) && x.ProcessId >= 0
            && Text(x.ProcessName, 128) && (x.Path is null || Text(x.Path, 1024)) && Text(x.State, 32) && Level(x.Peak)
            && (x.Signer is null || Text(x.Signer, 512)))
        && s.Effects.All(e => e is not null && Text(e.Clsid, 64) && Text(e.Name, 256) && (e.DllPath is null || Text(e.DllPath, 1024))
            && (e.Signer is null || Text(e.Signer, 512)))
        && s.Issues.All(i => i is not null && Severities.Contains(i.Severity) && Categories.Contains(i.Category) && Text(i.Title, 256)
            && Text(i.Detail, 1024) && Text(i.Technique, 32) && Text(i.Indicator, 1024))
        && Text(s.Posture.AudioService, 32) && Text(s.Posture.EndpointBuilder, 32) && s.Posture.AudioEngineCpuPercent is >= 0 and <= 100
        && (s.Posture.AudioEnginePath is null || Text(s.Posture.AudioEnginePath, 1024)) && s.Posture.AudioEngineInstances >= 0
        && s.Posture.AudioErrors24h >= 0 && s.Posture.AudioWarnings24h >= 0
        && s.Warnings.All(w => Text(w, 512));

    private static bool Level(double value) => value is >= 0 and <= 1;

    private static bool Text(string? value, int max) => value is not null && value.Length <= max && !value.Any(char.IsControl);
}
