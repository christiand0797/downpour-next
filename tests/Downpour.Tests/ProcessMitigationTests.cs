using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class ProcessMitigationTests
{
    private static ProcessMitigationEntry Entry(string name, int pid = 100, bool cfg = true, bool acg = true, bool cig = true,
        bool block = true, bool dep = true, bool aslr = true, int instances = 1) =>
        new(name, pid, instances, cfg, acg, cig, block, dep, aslr);

    [Fact]
    public void PolicyBitsMapToTheDocumentedControls()
    {
        var all = ProcessMitigationProvider.Decode("chrome", 42, dep: 0x1, aslr: 0x3, dynamicCode: 0x1, cfg: 0x1, signature: 0x23);
        Assert.True(all.ControlFlowGuard);
        Assert.True(all.ArbitraryCodeGuard);
        Assert.True(all.CodeIntegrityGuard);
        Assert.True(all.BlocksNonMicrosoftDlls);
        Assert.True(all.Dep);
        Assert.True(all.Aslr);

        var none = ProcessMitigationProvider.Decode("chrome", 42, dep: 0, aslr: 0, dynamicCode: 0, cfg: 0, signature: 0);
        Assert.False(none.ControlFlowGuard || none.ArbitraryCodeGuard || none.CodeIntegrityGuard
            || none.BlocksNonMicrosoftDlls || none.Dep || none.Aslr);

        // Audit bits are not enforcement, and the module-dependency bit is not CIG.
        var auditOnly = ProcessMitigationProvider.Decode("chrome", 42, dep: 0, aslr: 0, dynamicCode: 0x8, cfg: 0, signature: 0x18);
        Assert.False(auditOnly.ArbitraryCodeGuard);
        Assert.False(auditOnly.CodeIntegrityGuard);
        Assert.False(auditOnly.BlocksNonMicrosoftDlls);
        Assert.True(ProcessMitigationProvider.Decode("chrome", 42, dep: 0, aslr: 0, dynamicCode: 0, cfg: 0, signature: 0x20).BlocksNonMicrosoftDlls);
    }

    [Fact]
    public void OneRowPerImageKeepsTheWorstInstance()
    {
        var rows = ProcessMitigationProvider.SelectRepresentatives([
            Entry("chrome", 10),
            Entry("chrome", 11, cfg: false, acg: false, cig: false, block: false),
            Entry("chrome", 12),
            Entry("notepad", 20),
        ]);

        var chrome = Assert.Single(rows, row => row.ProcessName == "chrome");
        Assert.Equal(3, chrome.InstanceCount);
        Assert.Equal(11, chrome.ProcessId);
        Assert.False(chrome.ControlFlowGuard);
    }

    [Fact]
    public void HighValueImagesComeBeforeWorseGenericOnes()
    {
        var rows = ProcessMitigationProvider.SelectRepresentatives([
            Entry("somegame", 1, cfg: false, acg: false, cig: false, block: false, dep: false, aslr: false),
            Entry("msedge", 2, cfg: false),
            Entry("cmd", 3, cfg: false),
        ]);

        Assert.Equal("msedge", rows[0].ProcessName);
        // A high-value image is listed before worse generic ones, but among the rest the most exposed comes first.
        Assert.Equal("somegame", rows[1].ProcessName);
        Assert.Equal("cmd", rows[^1].ProcessName);
        Assert.Equal(ProcessMitigationLimits.MaximumProcesses, ProcessMitigationProvider.SelectRepresentatives(
            Enumerable.Range(1, 100).Select(i => Entry($"proc{i}", i)).ToArray()).Count);
    }

    [Fact]
    public void SnapshotValidationBoundsEveryField()
    {
        var snapshot = new ProcessMitigationSnapshot(1, DateTimeOffset.UtcNow, [Entry("chrome")], 3, ["3 processes refused the query."]);
        Assert.True(ProcessMitigationClient.IsValid(snapshot));
        Assert.False(ProcessMitigationClient.IsValid(null));
        Assert.False(ProcessMitigationClient.IsValid(snapshot with { SchemaVersion = 2 }));
        Assert.False(ProcessMitigationClient.IsValid(snapshot with { Processes = [Entry("chrome", pid: 0)] }));
        Assert.False(ProcessMitigationClient.IsValid(snapshot with { Processes = [Entry("chrome", instances: 0)] }));
        Assert.False(ProcessMitigationClient.IsValid(snapshot with { Processes = [Entry(new string('a', 129))] }));
        Assert.False(ProcessMitigationClient.IsValid(snapshot with { RefusedCount = -1 }));
        Assert.False(ProcessMitigationClient.IsValid(snapshot with { CapturedAtUtc = DateTimeOffset.UtcNow.AddDays(3) }));
        Assert.False(ProcessMitigationClient.IsValid(snapshot with
        {
            Processes = Enumerable.Range(0, 65).Select(i => Entry($"p{i}", i + 1)).ToArray()
        }));
    }

    [Fact]
    public void CaptureReadsTheTestProcess()
    {
        var snapshot = new ProcessMitigationProvider().Capture();

        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.NotEmpty(snapshot.Processes);
        Assert.True(snapshot.Processes.Count <= ProcessMitigationLimits.MaximumProcesses);
        Assert.All(snapshot.Processes, entry => Assert.True(entry.InstanceCount >= 1 && entry.ProcessId > 4));
        // The scoring path is what the UI shows, so at least one representative must score in range.
        Assert.All(snapshot.Processes, entry =>
        {
            var assessment = ExploitMitigationPosture.Assess(ExploitMitigationPosture.FromEntry(entry));
            Assert.InRange(assessment.Score, 0, assessment.Maximum);
        });
    }
}
