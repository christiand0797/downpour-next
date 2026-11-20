namespace Downpour.Core;

public sealed record EgressSample(string ProcessName, string NetworkOwner, string CountryCode, long BytesOut, DateTimeOffset AtUtc);

public sealed record EgressAnomaly(string ProcessName, string NetworkOwner, string CountryCode, long BytesOut, double BaselineBytes, string Reason);

/// <summary>
/// Watches what leaves the PC. It keeps only the owning process name, the network owner and country of a destination —
/// never a remote address, URL or payload — so the baseline cannot become a browsing history. A finding needs both
/// novelty and volume: a process talking to a new network owner at ordinary volume is not an exfiltration signal, and a
/// high volume to an already known owner is not either. Nothing here blocks traffic.
/// </summary>
public sealed class EgressBaseline
{
    public const int MaximumProcesses = 512;
    public const long MinimumAnomalyBytes = 50L * 1024 * 1024;
    private const double VolumeMultiple = 5;

    private readonly Dictionary<string, ProcessHistory> _processes = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    private sealed class ProcessHistory
    {
        public HashSet<string> Owners { get; } = new(StringComparer.OrdinalIgnoreCase);
        public long TotalBytes;
        public long Samples;
        public double MeanBytes => Samples == 0 ? 0 : (double)TotalBytes / Samples;
    }

    /// <summary>Returns an anomaly for this sample (before folding it into the baseline) or null when it looks ordinary.</summary>
    public EgressAnomaly? Observe(EgressSample sample)
    {
        ArgumentNullException.ThrowIfNull(sample);
        if (string.IsNullOrWhiteSpace(sample.ProcessName) || sample.BytesOut < 0)
            throw new ArgumentException("The egress sample is outside its bounds.", nameof(sample));
        lock (_gate)
        {
            if (!_processes.TryGetValue(sample.ProcessName, out var history))
            {
                if (_processes.Count >= MaximumProcesses) return null;
                history = new ProcessHistory();
                _processes[sample.ProcessName] = history;
            }
            var owner = OwnerKey(sample);
            var novel = owner.Length > 0 && !history.Owners.Contains(owner);
            var baseline = history.MeanBytes;
            var volume = sample.BytesOut >= MinimumAnomalyBytes && (baseline <= 0 || sample.BytesOut >= baseline * VolumeMultiple);
            // Only a transfer large enough to matter makes an owner "known"; otherwise one short connection would
            // whitelist the owner before the transfer that deserves attention ever happens.
            if (novel && volume) history.Owners.Add(owner);
            history.TotalBytes = Math.Min(history.TotalBytes + sample.BytesOut, long.MaxValue / 4);
            history.Samples++;
            if (!novel || !volume) return null;
            return new EgressAnomaly(sample.ProcessName, sample.NetworkOwner, sample.CountryCode, sample.BytesOut, Math.Round(baseline),
                $"{sample.ProcessName} sent {sample.BytesOut / 1024d / 1024d:0.0} MB to a network owner never seen for it before ({owner}).");
        }
    }

    public double MeanFor(string processName)
    {
        lock (_gate) return _processes.TryGetValue(processName, out var history) ? Math.Round(history.MeanBytes) : 0;
    }

    private static string OwnerKey(EgressSample sample) =>
        string.IsNullOrWhiteSpace(sample.NetworkOwner) ? "" : $"{sample.NetworkOwner.Trim()} · {sample.CountryCode.Trim().ToUpperInvariant()}";
}
