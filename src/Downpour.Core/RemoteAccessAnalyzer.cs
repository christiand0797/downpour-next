using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>A TCP endpoint row with its owning process name.</summary>
public sealed record TcpEndpoint(bool Listening, int LocalPort, string RemoteAddress, int RemotePort, bool RemoteIsLoopback, int ProcessId, string ProcessName);

/// <summary>
/// Remote-access exposure rules from v29 downpour_remote_access.py: REMOTE_ACCESS_VECTORS (lines 35-47) for listening
/// and established ports, SUSPICIOUS_REMOTE_PROCESSES (lines 49-56) for running tools. The view keeps v29's
/// classification; findings (which raise alerts) are limited to high-confidence signals because several v29 "reverse
/// shell" ports (8080, 8443, 5555, 1234) are routinely used by development servers and adb.
/// </summary>
public static class RemoteAccessAnalyzer
{
    public static readonly IReadOnlyList<(string Vector, int[] Ports, string Risk, string Description)> Vectors =
    [
        ("rdp", [3389], "High", "Remote Desktop Protocol"),
        ("vnc", [5900, 5901, 5902], "Medium", "Virtual Network Computing"),
        ("teamviewer", [5938], "Medium", "TeamViewer"),
        ("anydesk", [7070], "Medium", "AnyDesk"),
        ("ssh", [22], "Medium", "Secure Shell"),
        ("telnet", [23], "High", "Telnet (unencrypted)"),
        ("reverse_tcp", [4444, 4445, 1234, 8080, 8443], "Critical", "Common reverse-shell ports"),
        ("cobalt_strike", [50050], "Critical", "Cobalt Strike default listener"),
        ("metasploit", [4444, 5555], "Critical", "Metasploit handler"),
        ("ngrok", [4040], "High", "ngrok tunnel"),
        ("winrm", [5985, 5986], "High", "Windows Remote Management"),
    ];

    /// <summary>Ports in v29 vectors that are used almost only by attack tooling.</summary>
    public static readonly IReadOnlySet<int> AttackOnlyPorts = new HashSet<int> { 4444, 4445, 50050 };

    /// <summary>SUSPICIOUS_REMOTE_PROCESSES, grouped so findings can be graded.</summary>
    public static readonly IReadOnlyDictionary<string, string> ToolCategories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["teamviewer.exe"] = "Remote support", ["anydesk.exe"] = "Remote support", ["ammyy.exe"] = "Remote support",
        ["radmin.exe"] = "Remote support", ["logmein.exe"] = "Remote support", ["screenconnect.exe"] = "Remote support",
        ["connectwise.exe"] = "Remote support", ["mstsc.exe"] = "Remote desktop client",
        ["ncat.exe"] = "Network relay", ["nc.exe"] = "Network relay", ["netcat.exe"] = "Network relay", ["plink.exe"] = "Network relay",
        ["putty.exe"] = "SSH client", ["psexec.exe"] = "Remote execution", ["psexecsvc.exe"] = "Remote execution",
        ["remcos.exe"] = "Remote access trojan", ["njrat.exe"] = "Remote access trojan", ["darkcomet.exe"] = "Remote access trojan",
        ["quasar.exe"] = "Remote access trojan",
    };

    public static (string Vector, string Risk, string Description)? Classify(int port)
    {
        foreach (var (vector, ports, risk, description) in Vectors)
            if (ports.Contains(port)) return (vector, risk, description);
        return null;
    }

    public static IReadOnlyList<RemoteAccessExposure> Exposures(IEnumerable<TcpEndpoint> endpoints)
    {
        var results = new List<RemoteAccessExposure>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var endpoint in endpoints)
        {
            if (endpoint.Listening)
            {
                if (Classify(endpoint.LocalPort) is not { } match) continue;
                if (!seen.Add($"L|{endpoint.LocalPort}|{endpoint.ProcessId}")) continue;
                results.Add(new(RemoteAccessKinds.Listener, match.Vector, match.Risk, match.Description, endpoint.LocalPort, "", endpoint.ProcessId, endpoint.ProcessName));
            }
            else if (!endpoint.RemoteIsLoopback)
            {
                // v29 _classify_connection: remote or local port on a vector; loopback skipped.
                var match = Classify(endpoint.RemotePort) ?? Classify(endpoint.LocalPort);
                if (match is not { } found) continue;
                var remote = $"{endpoint.RemoteAddress}:{endpoint.RemotePort}";
                if (!seen.Add($"C|{remote}|{endpoint.LocalPort}|{endpoint.ProcessId}")) continue;
                results.Add(new(RemoteAccessKinds.Connection, found.Vector, found.Risk, found.Description, endpoint.LocalPort, remote, endpoint.ProcessId, endpoint.ProcessName));
            }
        }
        return results;
    }

    public static IReadOnlyList<RemoteAccessTool> Tools(IEnumerable<(int ProcessId, string Name)> processes) =>
        processes
            .Where(process => ToolCategories.ContainsKey(process.Name))
            .Select(process => new RemoteAccessTool(process.ProcessId, process.Name, ToolCategories[process.Name]))
            .ToArray();

    public static IReadOnlyList<RemoteAccessFinding> Findings(bool? rdpEnabled, bool? nla, IReadOnlyList<RemoteAccessExposure> exposures, IReadOnlyList<RemoteAccessTool> tools)
    {
        var findings = new List<RemoteAccessFinding>();
        if (rdpEnabled == true && nla == false)
            findings.Add(new("HIGH", "T1021.001", "Remote Desktop is enabled without Network Level Authentication.", "rdp:nla-off"));
        foreach (var tool in tools.DistinctBy(tool => tool.ProcessName, StringComparer.OrdinalIgnoreCase))
        {
            var (severity, technique) = tool.Category switch
            {
                "Remote access trojan" => ("CRITICAL", "T1219"),
                "Network relay" => ("HIGH", "T1095"),
                "Remote execution" => ("HIGH", "T1569.002"),
                _ => ((string?)null, "")
            };
            if (severity is not null)
                findings.Add(new(severity, technique, $"{tool.Category} running: {tool.ProcessName} (PID {tool.ProcessId})", $"tool:{tool.ProcessName.ToLowerInvariant()}"));
        }
        foreach (var exposure in exposures.Where(exposure => AttackOnlyPorts.Contains(exposure.LocalPort) || AttackOnlyPorts.Contains(RemotePort(exposure))))
        {
            var port = AttackOnlyPorts.Contains(exposure.LocalPort) ? exposure.LocalPort : RemotePort(exposure);
            findings.Add(new("CRITICAL", "T1571",
                exposure.Kind == RemoteAccessKinds.Listener
                    ? $"{exposure.ProcessName} is listening on port {port} ({exposure.Description})"
                    : $"{exposure.ProcessName} is connected to {exposure.RemoteEndpoint} ({exposure.Description})",
                $"port:{exposure.Kind}:{port}:{exposure.ProcessName.ToLowerInvariant()}"));
        }
        return findings;
    }

    private static int RemotePort(RemoteAccessExposure exposure)
    {
        var colon = exposure.RemoteEndpoint.LastIndexOf(':');
        return colon > 0 && int.TryParse(exposure.RemoteEndpoint[(colon + 1)..], out var port) ? port : 0;
    }
}
