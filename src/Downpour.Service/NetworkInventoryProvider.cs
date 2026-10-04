using System.Net.NetworkInformation;
using Downpour.Contracts;

namespace Downpour.Service;

public sealed class NetworkInventoryProvider
{
    private const int MaximumInterfaces = 32;
    private const int MaximumConnections = 256;
    private const int MaximumTextLength = 256;
    private readonly object _gate = new();
    private readonly Dictionary<string, InterfaceBaseline> _baselines = new(StringComparer.OrdinalIgnoreCase);

    public NetworkInventorySnapshot Capture()
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var warnings = new List<string>();
            var interfaces = CaptureInterfaces(now, warnings);
            var connections = CaptureConnections(warnings, out var totalConnectionCount);
            return new NetworkInventorySnapshot(1, now, interfaces, connections, totalConnectionCount, warnings);
        }
    }

    private IReadOnlyList<NetworkInterfaceEntry> CaptureInterfaces(DateTimeOffset now, List<string> warnings)
    {
        NetworkInterface[] all;
        try
        {
            all = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (NetworkInformationException)
        {
            warnings.Add("Windows could not enumerate network interfaces.");
            return [];
        }

        var entries = new List<NetworkInterfaceEntry>(Math.Min(all.Length, MaximumInterfaces));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var networkInterface in all)
        {
            if (entries.Count >= MaximumInterfaces) break;
            try
            {
                var id = networkInterface.Id;
                var stats = networkInterface.GetIPv4Statistics();
                if (stats.BytesReceived < 0 || stats.BytesSent < 0) continue;

                long? receiveRate = null;
                long? sendRate = null;
                if (_baselines.TryGetValue(id, out var previous))
                {
                    var elapsed = (now - previous.CapturedAtUtc).TotalSeconds;
                    if (elapsed is > 0 and <= 30 && stats.BytesReceived >= previous.ReceivedBytes && stats.BytesSent >= previous.SentBytes)
                    {
                        receiveRate = Rate(stats.BytesReceived - previous.ReceivedBytes, elapsed);
                        sendRate = Rate(stats.BytesSent - previous.SentBytes, elapsed);
                    }
                }

                _baselines[id] = new InterfaceBaseline(now, stats.BytesReceived, stats.BytesSent);
                seen.Add(id);
                entries.Add(new NetworkInterfaceEntry(
                    Bound(networkInterface.Name),
                    Bound(networkInterface.Description),
                    networkInterface.OperationalStatus.ToString(),
                    receiveRate,
                    sendRate,
                    stats.BytesReceived,
                    stats.BytesSent));
            }
            catch (NetworkInformationException)
            {
                warnings.Add("A network interface changed or became unavailable during collection.");
            }
            catch (InvalidOperationException)
            {
                warnings.Add("A network interface changed or became unavailable during collection.");
            }
        }

        foreach (var stale in _baselines.Keys.Where(key => !seen.Contains(key)).ToArray()) _baselines.Remove(stale);
        if (all.Length > MaximumInterfaces) warnings.Add($"Interface display is limited to the first {MaximumInterfaces} of {all.Length} adapters.");
        if (entries.Count == 0) warnings.Add("No network interfaces were available for statistics.");
        return entries;
    }

    private static IReadOnlyList<NetworkConnectionEntry> CaptureConnections(List<string> warnings, out int totalCount)
    {
        try
        {
            var all = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            totalCount = all.Length;
            var rows = all.Take(MaximumConnections)
                .Select(connection => new NetworkConnectionEntry(
                    Bound(connection.LocalEndPoint.ToString()),
                    Bound(connection.RemoteEndPoint.ToString()),
                    connection.State.ToString()))
                .ToArray();
            if (all.Length > MaximumConnections) warnings.Add($"Connection display is limited to the first {MaximumConnections} of {all.Length} active TCP connections.");
            return rows;
        }
        catch (NetworkInformationException)
        {
            totalCount = 0;
            warnings.Add("Windows could not enumerate active TCP connections.");
            return [];
        }
        catch (PlatformNotSupportedException)
        {
            totalCount = 0;
            warnings.Add("Active TCP connection enumeration is unavailable on this platform.");
            return [];
        }
    }

    private static long Rate(long bytes, double elapsedSeconds)
    {
        var rate = bytes / elapsedSeconds;
        return !double.IsFinite(rate) || rate >= long.MaxValue ? long.MaxValue : Math.Max(0, (long)rate);
    }

    private static string Bound(string value) => value.Length <= MaximumTextLength ? value : value[..MaximumTextLength];

    private sealed record InterfaceBaseline(DateTimeOffset CapturedAtUtc, long ReceivedBytes, long SentBytes);
}
