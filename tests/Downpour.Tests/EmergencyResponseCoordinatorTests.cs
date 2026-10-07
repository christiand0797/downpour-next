using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class EmergencyResponseCoordinatorTests : IDisposable
{
    private readonly string _testDirectory;

    public EmergencyResponseCoordinatorTests()
    {
        _testDirectory = Path.Combine(Path.GetTempPath(), "DownpourTests_Emergency_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDirectory);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDirectory))
            {
                Directory.Delete(_testDirectory, recursive: true);
            }
        }
        catch
        {
            // Ignore cleanup failures in test teardown
        }
    }

    [Fact]
    public async Task CaptureSnapshotAsync_WithSimulatedData_CreatesValidSnapshotAndSavesToDisk()
    {
        var coordinator = new EmergencyResponseCoordinator(_testDirectory);

        var simulatedProcesses = new List<EmergencyProcessInfo>
        {
            new(101, "svchost.exe", @"C:\Windows\System32\svchost.exe", 15_000_000, DateTimeOffset.UtcNow.AddHours(-1), false, "", ""),
            new(202, "mimikatz.exe", @"C:\Users\victim\AppData\Local\Temp\mimikatz.exe", 8_000_000, DateTimeOffset.UtcNow.AddMinutes(-5), true, "Known attack tool", "T1003"),
            new(303, "evil.exe", @"C:\Users\Public\evil.exe", 4_000_000, DateTimeOffset.UtcNow.AddMinutes(-2), true, "Suspicious path", "T1036")
        };

        var simulatedConnections = new List<EmergencyConnectionInfo>
        {
            new("192.168.1.50:49200", "198.51.100.1:443", "Established", 202, "mimikatz.exe"),
            new("0.0.0.0:80", "0.0.0.0:0", "Listen", 101, "svchost.exe")
        };

        var snapshot = await coordinator.CaptureSnapshotAsync(simulatedProcesses, simulatedConnections);

        Assert.NotNull(snapshot);
        Assert.NotEmpty(snapshot.SnapshotId);
        Assert.Equal(3, snapshot.ProcessCount);
        Assert.Equal(2, snapshot.ConnectionCount);
        Assert.Equal(2, snapshot.SuspiciousProcessCount);
        Assert.Equal(64, snapshot.ForensicSealSha256.Length);
        Assert.True(File.Exists(snapshot.SnapshotFilePath));

        string fileContent = await File.ReadAllTextAsync(snapshot.SnapshotFilePath);
        Assert.Contains(snapshot.SnapshotId, fileContent);
        Assert.Contains("mimikatz.exe", fileContent);
    }

    [Theory]
    [InlineData("mimikatz.exe", @"C:\Tools\mimikatz.exe", true, "T1003/T1572")]
    [InlineData("psexec.exe", @"C:\Windows\System32\psexec.exe", true, "T1003/T1572")]
    [InlineData("nc.exe", @"C:\nc.exe", true, "T1003/T1572")]
    [InlineData("injected.exe", @"C:\Users\user\AppData\Local\Temp\injected.exe", true, "T1036/T1059")]
    [InlineData("payload.exe", @"C:\Users\Public\payload.exe", true, "T1036/T1059")]
    [InlineData("explorer.exe", @"C:\Windows\explorer.exe", false, "")]
    [InlineData("Downpour.Desktop.exe", @"C:\Program Files\Downpour\Downpour.Desktop.exe", false, "")]
    public void EvaluateProcess_IdentifiesSuspiciousNamesAndPathsCorrectly(
        string processName,
        string exePath,
        bool expectedSuspicious,
        string expectedTechnique)
    {
        var (isSuspicious, reason, technique) = EmergencyResponseCoordinator.EvaluateProcess(processName, exePath);

        Assert.Equal(expectedSuspicious, isSuspicious);
        if (expectedSuspicious)
        {
            Assert.NotEmpty(reason);
            Assert.Equal(expectedTechnique, technique);
        }
        else
        {
            Assert.Empty(reason);
            Assert.Empty(technique);
        }
    }

    [Fact]
    public async Task ExecuteActionAsync_GuardsSystemAlteringActionsUnderActionBroker()
    {
        var coordinator = new EmergencyResponseCoordinator(_testDirectory);

        var isolateResult = await coordinator.ExecuteActionAsync(EmergencyActionType.IsolateNetwork);
        Assert.Equal(EmergencyActionStatus.GuardedPendingAuthorization, isolateResult.Status);
        Assert.True(isolateResult.RequiresActionBroker);
        Assert.Contains("DN-008", isolateResult.Details);

        var restoreResult = await coordinator.ExecuteActionAsync(EmergencyActionType.RestoreNetwork);
        Assert.Equal(EmergencyActionStatus.GuardedPendingAuthorization, restoreResult.Status);
        Assert.True(restoreResult.RequiresActionBroker);

        var killResult = await coordinator.ExecuteActionAsync(EmergencyActionType.TerminateSuspicious);
        Assert.Equal(EmergencyActionStatus.GuardedPendingAuthorization, killResult.Status);
        Assert.True(killResult.RequiresActionBroker);
    }

    [Fact]
    public async Task ExecuteActionAsync_PermitsSafeActionsWithoutActionBroker()
    {
        var coordinator = new EmergencyResponseCoordinator(_testDirectory);

        var snapshotResult = await coordinator.ExecuteActionAsync(EmergencyActionType.SystemSnapshot);
        Assert.Equal(EmergencyActionStatus.Completed, snapshotResult.Status);
        Assert.False(snapshotResult.RequiresActionBroker);

        var forensicsResult = await coordinator.ExecuteActionAsync(EmergencyActionType.CollectForensics);
        Assert.Equal(EmergencyActionStatus.Completed, forensicsResult.Status);
        Assert.False(forensicsResult.RequiresActionBroker);

        var reportResult = await coordinator.ExecuteActionAsync(EmergencyActionType.ExportIrReport);
        Assert.Equal(EmergencyActionStatus.Completed, reportResult.Status);
        Assert.False(reportResult.RequiresActionBroker);

        var lockResult = await coordinator.ExecuteActionAsync(EmergencyActionType.LockWorkstation, isSimulated: true);
        Assert.Equal(EmergencyActionStatus.Completed, lockResult.Status);
        Assert.False(lockResult.RequiresActionBroker);
    }

    [Fact]
    public async Task ExecuteFullLockdownAsync_CapturesSnapshotAndAuditsGuardedActions()
    {
        var coordinator = new EmergencyResponseCoordinator(_testDirectory);

        var outcome = await coordinator.ExecuteFullLockdownAsync(isSimulated: true);

        Assert.NotNull(outcome);
        Assert.NotEmpty(outcome.ResponseId);
        Assert.NotNull(outcome.SnapshotPath);
        Assert.True(File.Exists(outcome.SnapshotPath));
        Assert.Equal(4, outcome.ActionResults.Count);

        // Snapshot is completed
        Assert.Contains(outcome.ActionResults, r => r.ActionType == EmergencyActionType.SystemSnapshot && r.Status == EmergencyActionStatus.Completed);
        // Network isolation is guarded
        Assert.Contains(outcome.ActionResults, r => r.ActionType == EmergencyActionType.IsolateNetwork && r.Status == EmergencyActionStatus.GuardedPendingAuthorization);
        // Process termination is guarded
        Assert.Contains(outcome.ActionResults, r => r.ActionType == EmergencyActionType.TerminateSuspicious && r.Status == EmergencyActionStatus.GuardedPendingAuthorization);
    }

    [Fact]
    public void GenerateIncidentResponseReport_FormatsCompleteMarkdownReport()
    {
        var coordinator = new EmergencyResponseCoordinator(_testDirectory);

        var snapshot = new EmergencySnapshot(
            SnapshotId: "test_resp_123",
            TimestampUtc: DateTimeOffset.UtcNow,
            MachineName: "TEST-HOST",
            OsVersion: "Windows 11 Pro",
            ProcessCount: 2,
            ConnectionCount: 1,
            SuspiciousProcessCount: 1,
            Processes: new List<EmergencyProcessInfo>
            {
                new(500, "legit.exe", @"C:\Windows\legit.exe", 10_000_000, DateTimeOffset.UtcNow, false, "", ""),
                new(666, "mimikatz.exe", @"C:\Temp\mimikatz.exe", 5_000_000, DateTimeOffset.UtcNow, true, "Known attack tool", "T1003")
            },
            Connections: new List<EmergencyConnectionInfo>
            {
                new("10.0.0.5:5555", "10.0.0.1:443", "Established", 666, "mimikatz.exe")
            },
            ForensicSealSha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            SnapshotFilePath: @"C:\snapshots\test.json");

        var logs = new List<EmergencyLogEntry>
        {
            new(DateTimeOffset.UtcNow, EmergencyLogSeverity.Warning, "Lockdown Trigger", "Full panic button pressed"),
            new(DateTimeOffset.UtcNow, EmergencyLogSeverity.Info, "Snapshot", "Snapshot created")
        };

        string report = coordinator.GenerateIncidentResponseReport(snapshot, logs);

        Assert.Contains("# Incident Response (IR) Forensic Report", report);
        Assert.Contains("test_resp_123", report);
        Assert.Contains("TEST-HOST", report);
        Assert.Contains("mimikatz.exe", report);
        Assert.Contains("DN-008", report);
        Assert.Contains("Full panic button pressed", report);
    }
}
