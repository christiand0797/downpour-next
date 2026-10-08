using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class HiddenProcessTests
{
    private static readonly DateTimeOffset Scan = new(2026, 10, 8, 12, 0, 0, TimeSpan.Zero);
    private static readonly HashSet<int> Listed = [100, 104, 108];

    [Fact]
    public void RunningProcessMissingFromBothListsIsHidden()
    {
        var hidden = Assert.Single(HiddenProcessAnalyzer.Find(Listed, Listed,
            [new ProbedProcess(220, true, @"C:\Users\a\AppData\Local\Temp\svch0st.exe", Scan.AddHours(-3))], Scan));
        Assert.Equal(220, hidden.ProcessId);
        var finding = Assert.Single(HiddenProcessAnalyzer.ToFindings([hidden]));
        Assert.Equal("CRITICAL", finding.Severity);
        Assert.Equal("T1014", finding.Technique);
        Assert.Equal(SecurityFindingCatalog.Rootkit, finding.Source);
        Assert.Contains("svch0st.exe", finding.Summary);
    }

    [Fact]
    public void ChurnZombiesAndSystemPidsAreNeverReported()
    {
        ProbedProcess[] probed =
        [
            new(4, true, "System", Scan.AddDays(-1)),                       // System
            new(300, false, @"C:\x\exited.exe", Scan.AddHours(-1)),          // zombie: exited but still referenced
            new(304, true, @"C:\x\new.exe", Scan.AddSeconds(1)),             // started during the scan
            new(308, true, @"C:\x\appeared.exe", Scan.AddMinutes(-5)),       // shows up in the second list
            new(312, true, null, null),                                      // start time unknown
        ];
        Assert.Empty(HiddenProcessAnalyzer.Find(Listed, new HashSet<int>(Listed) { 308 }, probed, Scan));
    }

    [Fact]
    public void LiveScanOnThisPcFindsNothingHidden()
    {
        var hidden = HiddenProcessMonitor.Scan(CancellationToken.None);
        Assert.Empty(hidden);
    }
}
