namespace Downpour.Core;

/// <summary>
/// A local, per-key running baseline (Welford mean/variance). It answers "is this value unusual for this machine?"
/// with a z-score and never leaves memory. A standard deviation floor keeps tiny, steady series from flagging
/// negligible changes, and a minimum sample count prevents a baseline from judging the first few observations.
/// </summary>
public sealed class BehaviorBaseline(int minimumSamples = 5, double deviationFloor = 0.5)
{
    private readonly Dictionary<string, (double Mean, double M2, int Count)> _series = new(StringComparer.OrdinalIgnoreCase);

    public int MinimumSamples { get; } = Math.Max(2, minimumSamples);
    public double DeviationFloor { get; } = deviationFloor > 0 ? deviationFloor : 0.5;

    public void Observe(string key, double value)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Length > 200 || !double.IsFinite(value)) return;
        var (mean, m2, count) = _series.GetValueOrDefault(key);
        count++;
        var delta = value - mean;
        mean += delta / count;
        m2 += delta * (value - mean);
        _series[key] = (mean, m2, count);
    }

    public int SampleCount(string key) => _series.TryGetValue(key, out var series) ? series.Count : 0;

    /// <summary>Absolute deviation in standard deviations, or null until the key has enough samples.</summary>
    public double? Score(string key, double value)
    {
        if (!_series.TryGetValue(key, out var series) || series.Count < MinimumSamples || !double.IsFinite(value)) return null;
        var variance = series.Count > 1 ? series.M2 / (series.Count - 1) : 0;
        var deviation = Math.Max(Math.Sqrt(Math.Max(0, variance)), DeviationFloor);
        return Math.Abs(value - series.Mean) / deviation;
    }

    public bool IsUnusual(string key, double value, double threshold = 3) =>
        Score(key, value) is { } score && score >= threshold;

    public void Reset(string key) => _series.Remove(key);
}
