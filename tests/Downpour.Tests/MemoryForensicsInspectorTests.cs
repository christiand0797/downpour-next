using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class MemoryForensicsInspectorTests
{
    [Fact]
    public void InspectProcessIdentifiesNormalProcessAsClean()
    {
        var proc = new ProcessDescriptor(
            ProcessId: 1001,
            ProcessName: "notepad.exe",
            ExecutablePath: @"C:\Windows\System32\notepad.exe",
            WorkingSetBytes: 15L * 1024 * 1024,
            ThreadCount: 4);

        var result = MemoryForensicsInspector.InspectProcess(proc);

        Assert.Equal("Clean", result.Classification);
        Assert.Equal("CLEAN", result.Severity);
        Assert.Equal(0, result.InjectionScore);
        Assert.Equal("None", result.SuspectedTechnique);
        Assert.Empty(result.Findings);
    }

    [Theory]
    [InlineData("svch0st.exe")]
    [InlineData("scvhost.exe")]
    [InlineData("lsas.exe")]
    [InlineData("win1ogon.exe")]
    [InlineData("taskmngr.exe")]
    public void InspectProcessFlagsTypoSquattedProcessNames(string fakeName)
    {
        var proc = new ProcessDescriptor(
            ProcessId: 2002,
            ProcessName: fakeName,
            ExecutablePath: @"C:\Program Files\Fake\test.exe",
            WorkingSetBytes: 10L * 1024 * 1024,
            ThreadCount: 2);

        var result = MemoryForensicsInspector.InspectProcess(proc);

        Assert.True(result.InjectionScore >= 35);
        Assert.NotEqual("Clean", result.Classification);
        Assert.Contains("T1036", result.SuspectedTechnique);
        Assert.Contains(result.Findings, f => f.Contains("Typo-squatted"));
    }

    [Fact]
    public void InspectProcessDetectsCoreSystemBinaryOutsideSystem32()
    {
        var proc = new ProcessDescriptor(
            ProcessId: 3003,
            ProcessName: "svchost.exe",
            ExecutablePath: @"C:\Users\JohnDoe\AppData\Local\Temp\svchost.exe",
            WorkingSetBytes: 8L * 1024 * 1024,
            ThreadCount: 3);

        var result = MemoryForensicsInspector.InspectProcess(proc);

        Assert.True(result.InjectionScore >= 50);
        Assert.Equal("Injected", result.Classification);
        Assert.Contains("T1036.005", result.SuspectedTechnique);
        Assert.Contains(result.Findings, f => f.Contains("outside System32"));
        Assert.Contains(result.Findings, f => f.Contains("temporary"));
    }

    [Fact]
    public void InspectProcessCorrelatesSecurityAlertsForProcessInjection()
    {
        var proc = new ProcessDescriptor(
            ProcessId: 4444,
            ProcessName: "spoolsv.exe",
            ExecutablePath: @"C:\Windows\System32\spoolsv.exe",
            WorkingSetBytes: 20L * 1024 * 1024,
            ThreadCount: 6);

        var alert = new SecurityAlert(
            AlertId: "4444",
            Title: "Process Hollowing Detected",
            Severity: "CRITICAL",
            Technique: "T1055.012 Process Hollowing",
            LogName: "Microsoft-Windows-Sysmon/Operational",
            Provider: "Sysmon",
            EventId: 8,
            RecordId: 101,
            EventTimeUtc: DateTimeOffset.UtcNow,
            FirstSeenUtc: DateTimeOffset.UtcNow,
            LastSeenUtc: DateTimeOffset.UtcNow,
            Occurrences: 1,
            State: "Open",
            IsVerified: true);

        var alertMap = new Dictionary<int, List<SecurityAlert>>
        {
            [4444] = [alert]
        };

        var result = MemoryForensicsInspector.InspectProcess(proc, alertMap);

        Assert.True(result.InjectionScore >= 45);
        Assert.Contains("T1055", result.SuspectedTechnique);
        Assert.Contains(result.Findings, f => f.Contains("Process Hollowing Detected"));
    }

    [Fact]
    public async Task ScanAsyncWithSimulatedProcessesGeneratesAccurateSummary()
    {
        var simulated = new List<ProcessDescriptor>
        {
            // 1. Injected
            new(101, "svchost.exe", @"C:\Temp\svchost.exe", 10 * 1024 * 1024, 2),
            // 2. Suspicious
            new(102, "scvhost.exe", @"C:\ProgramData\test.exe", 12 * 1024 * 1024, 3),
            // 3. Clean
            new(103, "calc.exe", @"C:\Windows\System32\calc.exe", 8 * 1024 * 1024, 4),
            // 4. Clean
            new(104, "notepad.exe", @"C:\Windows\System32\notepad.exe", 6 * 1024 * 1024, 2)
        };

        var summary = await MemoryForensicsInspector.ScanAsync(simulatedProcesses: simulated);

        Assert.Equal(4, summary.TotalProcessesScanned);
        Assert.Equal(1, summary.InjectedCount);
        Assert.Equal(1, summary.SuspiciousCount);
        Assert.Equal(2, summary.CleanCount);
        Assert.Equal(2, summary.HighRiskProcesses.Count);
        Assert.Contains("Process termination", summary.SecurityNotice);
    }

    [Fact]
    public async Task GenerateReportFormatsComprehensiveSections()
    {
        var simulated = new List<ProcessDescriptor>
        {
            new(505, "svch0st.exe", @"C:\Users\Admin\Downloads\svch0st.exe", 14 * 1024 * 1024, 1)
        };

        var summary = await MemoryForensicsInspector.ScanAsync(simulatedProcesses: simulated);
        var reportText = MemoryForensicsInspector.GenerateReport(summary);

        Assert.Contains("=== DOWNPOUR MEMORY FORENSICS & INJECTION REPORT ===", reportText);
        Assert.Contains("=== HIGH-RISK PROCESSES & INJECTION FINDINGS", reportText);
        Assert.Contains("=== SAFETY & EXECUTION POLICY NOTICE ===", reportText);
        Assert.Contains("PID 505", reportText);
        Assert.Contains("svch0st.exe", reportText);
        Assert.Contains(summary.SecurityNotice, reportText);
    }
}
