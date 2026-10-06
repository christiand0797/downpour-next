using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class RemoteAccessTests
{
    private static TcpEndpoint Listen(int port, string process = "svc.exe") => new(true, port, "0.0.0.0", 0, false, 100, process);
    private static TcpEndpoint Connect(int remotePort, string remote = "203.0.113.5", bool loopback = false, string process = "app.exe") =>
        new(false, 50000, remote, remotePort, loopback, 200, process);

    [Fact]
    public void ListenersAndConnectionsAreClassifiedWithV29Vectors()
    {
        var exposures = RemoteAccessAnalyzer.Exposures([Listen(3389), Listen(80), Connect(5900), Connect(4444, "127.0.0.1", loopback: true), Listen(3389)]);
        Assert.Equal(2, exposures.Count);
        Assert.Contains(exposures, e => e.Kind == RemoteAccessKinds.Listener && e.Vector == "rdp" && e.Risk == "High");
        Assert.Contains(exposures, e => e.Kind == RemoteAccessKinds.Connection && e.Vector == "vnc" && e.RemoteEndpoint == "203.0.113.5:5900");
    }

    [Fact]
    public void OverlappingDevPortsAreShownButDoNotRaiseFindings()
    {
        var exposures = RemoteAccessAnalyzer.Exposures([Listen(8080, "node.exe"), Listen(5555, "adb.exe")]);
        Assert.All(exposures, e => Assert.Equal("Critical", e.Risk)); // v29 classification preserved in the view
        Assert.Empty(RemoteAccessAnalyzer.Findings(false, true, exposures, []));
    }

    [Fact]
    public void AttackOnlyPortsRaiseCriticalFindings()
    {
        var exposures = RemoteAccessAnalyzer.Exposures([Listen(4444, "x.exe"), Connect(50050, process: "beacon.exe")]);
        var findings = RemoteAccessAnalyzer.Findings(false, true, exposures, []);
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("CRITICAL", f.Severity));
    }

    [Theory]
    [InlineData(true, false, 1)]
    [InlineData(true, true, 0)]
    [InlineData(false, false, 0)]
    [InlineData(null, null, 0)]
    public void RdpWithoutNlaIsHigh(bool? enabled, bool? nla, int expected) =>
        Assert.Equal(expected, RemoteAccessAnalyzer.Findings(enabled, nla, [], []).Count(f => f.Indicator == "rdp:nla-off" && f.Severity == "HIGH"));

    [Fact]
    public void ToolsAreGradedByCategory()
    {
        var tools = RemoteAccessAnalyzer.Tools([(1, "TeamViewer.exe"), (2, "remcos.exe"), (3, "nc.exe"), (4, "PsExec.exe"), (5, "notepad.exe")]);
        Assert.Equal(4, tools.Count);
        var findings = RemoteAccessAnalyzer.Findings(null, null, [], tools);
        Assert.Contains(findings, f => f.Severity == "CRITICAL" && f.Summary.Contains("remcos.exe"));
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Summary.Contains("nc.exe"));
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Summary.Contains("PsExec.exe"));
        Assert.DoesNotContain(findings, f => f.Summary.Contains("TeamViewer")); // shown in the view, not alerted
    }

    [Theory]
    [InlineData(0x3D0D, 3389)]
    [InlineData(0x5000, 80)]
    [InlineData(0x0000BB01, 443)]
    public void PortsAreDecodedFromNetworkByteOrder(int raw, int port) =>
        Assert.Equal(port, RemoteAccessProvider.Port(raw));

    [Fact]
    public void LiveCaptureIsValid()
    {
        var snapshot = new RemoteAccessProvider().Capture();
        Assert.True(RemoteAccessClient.IsValid(snapshot), string.Join(" | ", snapshot.Warnings));
        Assert.All(snapshot.Exposures, e => Assert.InRange(e.LocalPort, 0, 65535));
    }

    [Fact]
    public void FindingsMapIntoTheTriageBridge()
    {
        var snapshot = new RemoteAccessSnapshot(1, DateTimeOffset.UtcNow, true, false, 3389, [], [],
            RemoteAccessAnalyzer.Findings(true, false, [], []), []);
        var mapped = Assert.Single(SecurityFindingMapper.FromRemoteAccess(snapshot));
        Assert.Equal(SecurityFindingCatalog.RemoteAccess, mapped.Source);
        Assert.Equal("rdp:nla-off", mapped.Indicator);
    }
}
