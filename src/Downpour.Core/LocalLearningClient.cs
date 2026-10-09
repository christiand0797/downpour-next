using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class LocalLearningClient(string pipeName = LocalLearningClient.PipeName)
{
    public const string PipeName = "Downpour.LocalLearning.v1";
    private static readonly HashSet<string> States = ["paused", "unavailable", "learning", "attention", "partial", "observing"];
    private static readonly HashSet<string> MetricStates = ["paused", "unavailable", "learning", "unusual", "typical"];
    private static readonly HashSet<string> Routes = ["threats", "network", "processes", "security-events"];

    public async Task<LocalLearningSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var result = await BoundedJson.DeserializeFramedAsync<LocalLearningSnapshot>(pipe, timeout.Token);
            return IsValid(result, DateTimeOffset.UtcNow) ? result : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException) { return null; }
    }

    public static bool IsValid(LocalLearningSnapshot? s, DateTimeOffset now) =>
        s is { SchemaVersion: 1, Metrics.Count: 4, Recommendations.Count: <= 8, Warnings.Count: <= 8 }
        && s.CapturedAtUtc >= now.AddMinutes(-2) && s.CapturedAtUtc <= now.AddMinutes(1)
        && States.Contains(s.State) && s.HistoryBuckets is >= 0 and <= LocalLearningEngine.MaximumBuckets
        && (s.LastObservationUtc is null || s.LastObservationUtc <= now.AddMinutes(1))
        && s.Metrics.Select(m => m?.Id).SequenceEqual(LocalLearningEngine.MetricIds)
        && s.Metrics.All(m => m is not null && MetricStates.Contains(m.State) && Number(m.Current) && Number(m.Normal)
            && Number(m.Threshold) && m.BaselineBuckets >= 0 && m.BaselineBuckets <= s.HistoryBuckets
            && (m.Id is not ("cpu" or "memory") || (m.Current is null or <= 100 && m.Normal is null or <= 100 && m.Threshold is null or <= 100))
            && (m.Id != "processes" || (m.Current is null or <= 100_000 && m.Normal is null or <= 100_000 && m.Threshold is null or <= 100_000))
            && ((m.Normal is null && m.Threshold is null) || (m.Normal is not null && m.Threshold >= m.Normal
                && m.BaselineBuckets >= LocalLearningEngine.MinimumBaselineBuckets))
            && (m.State switch
            {
                "typical" => m.Current is not null && m.Normal is not null && m.Current <= m.Threshold,
                "unusual" => m.Current is not null && m.Normal is not null && m.Current > m.Threshold,
                "learning" => m.Current is not null && m.Normal is null,
                _ => m.Current is null
            }))
        && s.Recommendations.All(r => r is not null && Text(r.Id, 48) && Text(r.Title, 128) && Text(r.Explanation, 768) && Routes.Contains(r.Route))
        && s.Recommendations.Select(r => r.Id).Distinct().Count() == s.Recommendations.Count
        && s.Warnings.All(w => Text(w, 512));

    private static bool Number(double? n) => n is null || (double.IsFinite(n.Value) && n >= 0 && n <= 1_000_000);
    private static bool Text(string? text, int limit) => text is { Length: > 0 } && text.Length <= limit && !text.Any(char.IsControl);
}
