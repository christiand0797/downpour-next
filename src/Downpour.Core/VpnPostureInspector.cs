using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Strictly read-only inspector for VPN interface posture, DNS leak risks, 
/// TCP connectivity validation, and OpenVPN profile reviews.
/// </summary>
public sealed class VpnPostureInspector
{
    private static readonly string[] VpnKeywords =
    [
        "tun", "tap", "wg", "wireguard", "ppp", "vpn", "proton", "nord",
        "mullvad", "surfshark", "expressvpn", "tailscale", "zerotier",
        "openvpn", "cisco", "anyconnect", "fortinet", "sonicwall",
        "softether", "wintun"
    ];

    private static readonly (string Provider, string[] Keywords)[] KnownProviders =
    [
        ("Mullvad", ["mullvad"]),
        ("ProtonVPN", ["proton", "protonvpn"]),
        ("NordVPN", ["nord", "nordvpn"]),
        ("ExpressVPN", ["expressvpn"]),
        ("Surfshark", ["surfshark"]),
        ("Tailscale", ["tailscale"]),
        ("WireGuard", ["wireguard", "wg"]),
        ("OpenVPN", ["openvpn", "tap-windows", "wintun"]),
        ("Cisco AnyConnect", ["cisco", "anyconnect"]),
        ("Fortinet FortiClient", ["fortinet", "forticlient"]),
        ("SonicWall NetExtender", ["sonicwall", "netextender"])
    ];

    private static readonly (string Host, int Port, string Label)[] StandardEndpoints =
    [
        ("1.1.1.1", 443, "Cloudflare DNS (1.1.1.1:443)"),
        ("8.8.8.8", 443, "Google DNS (8.8.8.8:443)"),
        ("www.microsoft.com", 443, "Microsoft CDN (TCP 443)")
    ];

    /// <summary>
    /// Evaluates current network interface state and assesses VPN connectivity and DNS leak risk.
    /// </summary>
    public VpnPostureSnapshot InspectPosture(IReadOnlyList<VpnProfileSummary>? importedProfiles = null)
    {
        var interfaces = new List<VpnInterfaceInfo>();
        var vpnDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var physicalDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var findings = new List<string>();

        NetworkInterface[] allInterfaces;
        try
        {
            allInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (Exception ex)
        {
            findings.Add($"Network interface enumeration error: {ex.Message}");
            allInterfaces = [];
        }

        string primaryProvider = "None";
        bool hasActiveVpn = false;

        foreach (var adapter in allInterfaces)
        {
            var isVpn = IsVpnInterface(adapter);
            var provider = isVpn ? DetectProvider(adapter) : "None";

            var ipAddresses = new List<string>();
            var dnsServers = new List<string>();
            string gateway = string.Empty;

            try
            {
                var ipProps = adapter.GetIPProperties();
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    ipAddresses.Add(unicast.Address.ToString());
                }

                foreach (var dns in ipProps.DnsAddresses)
                {
                    var dnsStr = dns.ToString();
                    dnsServers.Add(dnsStr);
                    if (adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        if (isVpn) vpnDns.Add(dnsStr);
                        else physicalDns.Add(dnsStr);
                    }
                }

                var gw = ipProps.GatewayAddresses.FirstOrDefault();
                if (gw != null && gw.Address != null)
                {
                    gateway = gw.Address.ToString();
                }
            }
            catch
            {
                // Unconfigured or transient interface properties
            }

            if (isVpn && adapter.OperationalStatus == OperationalStatus.Up)
            {
                hasActiveVpn = true;
                if (primaryProvider == "None" || primaryProvider == "Generic VPN")
                {
                    primaryProvider = provider;
                }
            }

            interfaces.Add(new VpnInterfaceInfo(
                adapter.Id,
                adapter.Name,
                adapter.Description,
                adapter.NetworkInterfaceType.ToString(),
                adapter.OperationalStatus.ToString(),
                ipAddresses,
                dnsServers,
                gateway,
                isVpn,
                provider));
        }

        // Assess DNS leak risk
        DnsLeakAssessment dnsLeak;
        if (!hasActiveVpn)
        {
            dnsLeak = new DnsLeakAssessment(
                HasLeakRisk: false,
                Status: "No VPN Connected",
                VpnDnsServers: [],
                PhysicalDnsServers: physicalDns.OrderBy(s => s).ToList(),
                Findings: ["Physical network DNS active; no encrypted VPN tunnel detected."]);
        }
        else
        {
            var nonTunnelDns = physicalDns.Where(dns => !vpnDns.Contains(dns) && !IsLoopbackAddress(dns)).ToList();
            if (nonTunnelDns.Count > 0)
            {
                findings.Add($"Split-tunnel DNS detected: {nonTunnelDns.Count} physical DNS server(s) configured outside the VPN tunnel.");
                dnsLeak = new DnsLeakAssessment(
                    HasLeakRisk: true,
                    Status: "Risk: Split-Tunnel DNS Detected",
                    VpnDnsServers: vpnDns.OrderBy(s => s).ToList(),
                    PhysicalDnsServers: physicalDns.OrderBy(s => s).ToList(),
                    Findings:
                    [
                        $"Potential DNS leak: Non-VPN adapter configured with DNS {string.Join(", ", nonTunnelDns)}.",
                        "DNS queries may leak outside the encrypted VPN tunnel to local physical gateways or ISP resolvers."
                    ]);
            }
            else
            {
                dnsLeak = new DnsLeakAssessment(
                    HasLeakRisk: false,
                    Status: "Protected / Tunnel DNS Only",
                    VpnDnsServers: vpnDns.OrderBy(s => s).ToList(),
                    PhysicalDnsServers: physicalDns.OrderBy(s => s).ToList(),
                    Findings: ["All active DNS queries are constrained to the encrypted VPN tunnel adapter."]);
            }
        }

        if (hasActiveVpn)
        {
            findings.Add($"Active VPN tunnel established via {primaryProvider}.");
        }
        else
        {
            findings.Add("No active VPN tunnel detected on host network interfaces.");
        }

        return new VpnPostureSnapshot(
            EvaluatedAtUtc: DateTimeOffset.UtcNow,
            IsVpnConnected: hasActiveVpn,
            PrimaryProvider: primaryProvider,
            Interfaces: interfaces,
            DnsLeak: dnsLeak,
            Profiles: importedProfiles ?? [],
            ConnectivityTests: [],
            KillSwitchGuarded: true,
            PostureFindings: findings);
    }

    /// <summary>
    /// Determines whether a network interface represents a VPN adapter based on interface type, name, and description.
    /// </summary>
    public static bool IsVpnInterface(NetworkInterface adapter)
    {
        if (adapter.NetworkInterfaceType is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel)
        {
            return true;
        }

        var text = $"{adapter.Name} {adapter.Description}".ToLowerInvariant();
        return VpnKeywords.Any(k => text.Contains(k));
    }

    /// <summary>
    /// Identifies the known commercial or open-source VPN provider for a given interface.
    /// </summary>
    public static string DetectProvider(NetworkInterface adapter)
    {
        var text = $"{adapter.Name} {adapter.Description}".ToLowerInvariant();
        foreach (var (provider, keywords) in KnownProviders)
        {
            if (keywords.Any(k => text.Contains(k)))
            {
                return provider;
            }
        }

        return "Generic VPN";
    }

    /// <summary>
    /// Safely parses an OpenVPN (.ovpn) configuration file to extract profile metadata without running code.
    /// </summary>
    public static VpnProfileSummary ParseOvpnProfile(string content, string fileName)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return new VpnProfileSummary(
                Name: Path.GetFileNameWithoutExtension(fileName),
                Protocol: "Unknown",
                RemoteHost: "None",
                RemotePort: null,
                Source: "Imported .ovpn");
        }

        string host = "None";
        int? port = null;
        string protocol = "UDP";

        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.StartsWith('#') || line.StartsWith(';') || string.IsNullOrEmpty(line))
            {
                continue;
            }

            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && parts[0].Equals("remote", StringComparison.OrdinalIgnoreCase))
            {
                host = parts[1];
                if (parts.Length >= 3 && int.TryParse(parts[2], out var parsedPort))
                {
                    port = parsedPort;
                }
            }
            else if (parts.Length >= 2 && parts[0].Equals("proto", StringComparison.OrdinalIgnoreCase))
            {
                protocol = parts[1].ToUpperInvariant();
            }
            else if (parts.Length >= 2 && parts[0].Equals("port", StringComparison.OrdinalIgnoreCase) && port == null)
            {
                if (int.TryParse(parts[1], out var parsedPort))
                {
                    port = parsedPort;
                }
            }
        }

        return new VpnProfileSummary(
            Name: Path.GetFileNameWithoutExtension(fileName),
            Protocol: $"OpenVPN ({protocol})",
            RemoteHost: host,
            RemotePort: port,
            Source: "Imported .ovpn");
    }

    /// <summary>
    /// Probes outbound TCP port 443 connectivity to test tunnel egress without ICMP (matching v29 TCP :443 probe).
    /// </summary>
    public async Task<IReadOnlyList<ConnectivityTestResult>> TestConnectivityAsync(CancellationToken token = default)
    {
        var results = new List<ConnectivityTestResult>();

        foreach (var (host, port, label) in StandardEndpoints)
        {
            if (token.IsCancellationRequested) break;

            var stopwatch = Stopwatch.StartNew();
            try
            {
                using var client = new TcpClient();
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));

                await client.ConnectAsync(host, port, timeoutCts.Token).ConfigureAwait(false);
                stopwatch.Stop();

                results.Add(new ConnectivityTestResult(
                    Target: label,
                    Reachable: true,
                    LatencyMs: (int)stopwatch.ElapsedMilliseconds,
                    Details: $"TCP connection succeeded in {stopwatch.ElapsedMilliseconds} ms"));
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                results.Add(new ConnectivityTestResult(
                    Target: label,
                    Reachable: false,
                    LatencyMs: (int)stopwatch.ElapsedMilliseconds,
                    Details: $"Unreachable: {ex.Message}"));
            }
        }

        return results;
    }

    /// <summary>
    /// Generates a comprehensive markdown report of the current VPN posture.
    /// </summary>
    public static string GenerateReport(VpnPostureSnapshot snapshot)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Downpour VPN & Tunnel Posture Audit Report");
        sb.AppendLine($"Generated: {snapshot.EvaluatedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine($"- **VPN State**: {(snapshot.IsVpnConnected ? "Connected" : "Disconnected")}");
        sb.AppendLine($"- **Primary Provider**: {snapshot.PrimaryProvider}");
        sb.AppendLine($"- **DNS Leak Assessment**: {snapshot.DnsLeak.Status}");
        sb.AppendLine($"- **Kill-Switch Guarded**: {(snapshot.KillSwitchGuarded ? "Yes (Protected under DN-008)" : "No")}");
        sb.AppendLine();

        sb.AppendLine("## DNS Leak Analysis");
        sb.AppendLine($"- **Risk Detected**: {snapshot.DnsLeak.HasLeakRisk}");
        sb.AppendLine($"- **Tunnel DNS Servers**: {(snapshot.DnsLeak.VpnDnsServers.Count > 0 ? string.Join(", ", snapshot.DnsLeak.VpnDnsServers) : "None")}");
        sb.AppendLine($"- **Physical DNS Servers**: {(snapshot.DnsLeak.PhysicalDnsServers.Count > 0 ? string.Join(", ", snapshot.DnsLeak.PhysicalDnsServers) : "None")}");
        foreach (var finding in snapshot.DnsLeak.Findings)
        {
            sb.AppendLine($"  - {finding}");
        }
        sb.AppendLine();

        sb.AppendLine("## Discovered Network Interfaces");
        foreach (var iface in snapshot.Interfaces)
        {
            sb.AppendLine($"### Adapter: {iface.Name} ({iface.Description})");
            sb.AppendLine($"- **Type**: {iface.InterfaceType} | **Status**: {iface.OperationalStatus}");
            sb.AppendLine($"- **VPN Classified**: {iface.IsVpn} (Provider: {iface.DetectedProvider})");
            sb.AppendLine($"- **IP Addresses**: {string.Join(", ", iface.IpAddresses)}");
            sb.AppendLine($"- **DNS Servers**: {string.Join(", ", iface.DnsServers)}");
            sb.AppendLine($"- **Gateway**: {(string.IsNullOrEmpty(iface.Gateway) ? "None" : iface.Gateway)}");
            sb.AppendLine();
        }

        if (snapshot.Profiles.Count > 0)
        {
            sb.AppendLine("## Known / Imported Profiles");
            foreach (var profile in snapshot.Profiles)
            {
                sb.AppendLine($"- **{profile.Name}**: {profile.Protocol} -> {profile.RemoteHost}:{(profile.RemotePort?.ToString() ?? "Default")} ({profile.Source})");
            }
            sb.AppendLine();
        }

        if (snapshot.ConnectivityTests.Count > 0)
        {
            sb.AppendLine("## Outbound TCP Connectivity Probes");
            foreach (var probe in snapshot.ConnectivityTests)
            {
                sb.AppendLine($"- **{probe.Target}**: {(probe.Reachable ? $"[OK] {probe.LatencyMs}ms" : "[FAIL]")} - {probe.Details}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine("Downpour Next Native Security Platform | Read-Only Network Inspection");
        return sb.ToString();
    }

    private static bool IsLoopbackAddress(string ipStr)
    {
        return IPAddress.TryParse(ipStr, out var ip) && IPAddress.IsLoopback(ip);
    }
}
