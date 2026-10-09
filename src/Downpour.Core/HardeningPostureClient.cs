using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class HardeningPostureClient(string pipeName = HardeningPostureClient.PipeName)
{
    public const string PipeName = "Downpour.HardeningPosture.v1";
    private const int MaximumChecks = 64;
    private const int MaximumText = 512;
    private static readonly HashSet<string> Severities = new(StringComparer.Ordinal) { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

    public async Task<HardeningPostureSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            // A cold capture runs several WMI queries with 5 s timeouts each.
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);

            var snapshot = await BoundedJson.DeserializeAsync<HardeningPostureSnapshot>(pipe, timeout.Token);
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

    public static bool IsValid(HardeningPostureSnapshot? snapshot) =>
        snapshot is not null
        && snapshot.SchemaVersion == 1
        && snapshot.Checks is not null
        && snapshot.Warnings is not null
        && snapshot.Checks.Count <= MaximumChecks
        && snapshot.Warnings.Count <= MaximumChecks
        && snapshot.Warnings.All(warning => warning is not null && warning.Length <= MaximumText)
        && snapshot.Checks.All(check => check is not null
            && Text(check.Id, 64) && check.Id.Length > 0 && Text(check.Title, 128) && Text(check.Technique, 32) && Text(check.Detail, MaximumText)
            && PostureStates.All.Contains(check.State) && Severities.Contains(check.Severity)
            && (check.Category is null || Text(check.Category, 64)) && (check.Fix is null || Text(check.Fix, MaximumText))
            && (check.SettingsUri is null || HardeningGuidance.AllowedUris.Contains(check.SettingsUri)));

    private static bool Text(string? value, int max) => value is not null && value.Length <= max;
}
