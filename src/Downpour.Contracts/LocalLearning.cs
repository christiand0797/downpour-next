namespace Downpour.Contracts;

/// <summary>Read-only explanations produced locally from existing aggregate sensors. No model/API calls or actions.</summary>
public sealed record LocalLearningSnapshot(int SchemaVersion, DateTimeOffset CapturedAtUtc, string State,
    DateTimeOffset? LastObservationUtc, int HistoryBuckets, IReadOnlyList<LocalMetricReading> Metrics,
    IReadOnlyList<LocalRecommendation> Recommendations, IReadOnlyList<string> Warnings);

public sealed record LocalMetricReading(string Id, double? Current, double? Normal, double? Threshold,
    int BaselineBuckets, string State);

public sealed record LocalRecommendation(string Id, string Title, string Explanation, string Route);
