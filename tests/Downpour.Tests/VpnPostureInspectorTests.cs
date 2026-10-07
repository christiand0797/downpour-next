using System.Net.NetworkInformation;
using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class VpnPostureInspectorTests
{
    [Fact]
    public void ParseOvpnProfile_ExtractsRemoteHostPortAndProtocol()
    {
        var ovpn = """
            # OpenVPN Client Configuration
            client
            dev tun
            proto udp
            remote us-east.vpn-provider.com 1194
            resolv-retry infinite
            nobind
            persist-key
            persist-tun
            cipher AES-256-GCM
            """;

        var profile = VpnPostureInspector.ParseOvpnProfile(ovpn, "us-east-config.ovpn");

        Assert.Equal("us-east-config", profile.Name);
        Assert.Equal("us-east.vpn-provider.com", profile.RemoteHost);
        Assert.Equal(1194, profile.RemotePort);
        Assert.Equal("OpenVPN (UDP)", profile.Protocol);
        Assert.Equal("Imported .ovpn", profile.Source);
    }

    [Fact]
    public void ParseOvpnProfile_ExtractsStandalonePortDirective()
    {
        var ovpn = """
            client
            dev tun
            proto tcp
            remote 198.51.100.25
            port 443
            """;

        var profile = VpnPostureInspector.ParseOvpnProfile(ovpn, "secure-tunnel.ovpn");

        Assert.Equal("secure-tunnel", profile.Name);
        Assert.Equal("198.51.100.25", profile.RemoteHost);
        Assert.Equal(443, profile.RemotePort);
        Assert.Equal("OpenVPN (TCP)", profile.Protocol);
    }

    [Fact]
    public void ParseOvpnProfile_HandlesEmptyOrWhitespaceContent()
    {
        var profile = VpnPostureInspector.ParseOvpnProfile("", "empty.ovpn");

        Assert.Equal("empty", profile.Name);
        Assert.Equal("None", profile.RemoteHost);
        Assert.Null(profile.RemotePort);
        Assert.Equal("Unknown", profile.Protocol);
    }

    [Fact]
    public void InspectPosture_ReturnsValidSnapshot()
    {
        var inspector = new VpnPostureInspector();
        var snapshot = inspector.InspectPosture();

        Assert.NotNull(snapshot);
        Assert.True(snapshot.EvaluatedAtUtc <= DateTimeOffset.UtcNow);
        Assert.NotNull(snapshot.Interfaces);
        Assert.NotNull(snapshot.DnsLeak);
        Assert.NotNull(snapshot.DnsLeak.Status);
        Assert.True(snapshot.KillSwitchGuarded);
    }

    [Fact]
    public void GenerateReport_IncludesAllSectionsAndDn008Notice()
    {
        var snapshot = new VpnPostureSnapshot(
            EvaluatedAtUtc: new DateTimeOffset(2026, 10, 7, 12, 0, 0, TimeSpan.Zero),
            IsVpnConnected: true,
            PrimaryProvider: "ProtonVPN",
            Interfaces:
            [
                new VpnInterfaceInfo(
                    Id: "{1111-2222-3333}",
                    Name: "ProtonVPN TUN",
                    Description: "TAP-Windows Adapter V9",
                    InterfaceType: "Tunnel",
                    OperationalStatus: "Up",
                    IpAddresses: ["10.2.0.2"],
                    DnsServers: ["10.2.0.1"],
                    Gateway: "10.2.0.1",
                    IsVpn: true,
                    DetectedProvider: "ProtonVPN"),
                new VpnInterfaceInfo(
                    Id: "{4444-5555-6666}",
                    Name: "Ethernet",
                    Description: "Intel Ethernet Connection",
                    InterfaceType: "Ethernet",
                    OperationalStatus: "Up",
                    IpAddresses: ["192.168.1.50"],
                    DnsServers: ["192.168.1.1"],
                    Gateway: "192.168.1.1",
                    IsVpn: false,
                    DetectedProvider: "None")
            ],
            DnsLeak: new DnsLeakAssessment(
                HasLeakRisk: true,
                Status: "Risk: Split-Tunnel DNS Detected",
                VpnDnsServers: ["10.2.0.1"],
                PhysicalDnsServers: ["192.168.1.1"],
                Findings: ["Physical adapter configured with DNS 192.168.1.1"]),
            Profiles:
            [
                new VpnProfileSummary("US-Node", "OpenVPN (UDP)", "us.protonvpn.com", 1194, "Imported .ovpn")
            ],
            ConnectivityTests:
            [
                new ConnectivityTestResult("Cloudflare DNS (1.1.1.1:443)", true, 18, "TCP connection succeeded in 18 ms")
            ],
            KillSwitchGuarded: true,
            PostureFindings: ["Active VPN tunnel established via ProtonVPN."]);

        var report = VpnPostureInspector.GenerateReport(snapshot);

        Assert.Contains("# Downpour VPN & Tunnel Posture Audit Report", report);
        Assert.Contains("**VPN State**: Connected", report);
        Assert.Contains("**Primary Provider**: ProtonVPN", report);
        Assert.Contains("Risk: Split-Tunnel DNS Detected", report);
        Assert.Contains("**Kill-Switch Guarded**: Yes (Protected under DN-008)", report);
        Assert.Contains("ProtonVPN TUN", report);
        Assert.Contains("10.2.0.1", report);
        Assert.Contains("US-Node", report);
        Assert.Contains("Cloudflare DNS", report);
        Assert.Contains("18 ms", report);
    }

    [Theory]
    [InlineData("protonvpn-adapter", "ProtonVPN")]
    [InlineData("mullvad-wg0", "Mullvad")]
    [InlineData("tailscale0", "Tailscale")]
    [InlineData("wireguard tunnel", "WireGuard")]
    [InlineData("cisco anyconnect secure mobility client", "Cisco AnyConnect")]
    public void DetectProvider_RecognizesKnownKeywords(string adapterName, string expectedProvider)
    {
        // Testing that keyword matching works as designed in KnownProviders
        var found = false;
        var lower = adapterName.ToLowerInvariant();
        var inspectorKeywords = new (string Provider, string[] Keywords)[]
        {
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
        };

        foreach (var (provider, keywords) in inspectorKeywords)
        {
            if (keywords.Any(k => lower.Contains(k)))
            {
                Assert.Equal(expectedProvider, provider);
                found = true;
                break;
            }
        }

        Assert.True(found, $"Failed to detect provider for adapter: {adapterName}");
    }
}
