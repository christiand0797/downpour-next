using System.Diagnostics;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Xunit;

namespace Downpour.Tests;

public sealed class ProcessTerminationActionTests : IDisposable
{
    private readonly string _testStateDir;
    private readonly string _auditLogPath;
    private readonly ActionAuditLog _auditLog;
    private readonly ActionConsentStore _consentStore;
    private readonly SensorSettingsStore _settingsStore;
    private readonly ProcessTerminationExecutor _executor;
    private readonly ProcessTerminationActionHandler _handler;

    public ProcessTerminationActionTests()
    {
        _testStateDir = Path.Combine(Path.GetTempPath(), "downpour_test_procterm_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testStateDir);
        _auditLogPath = Path.Combine(_testStateDir, "test-audit.v1.jsonl");
        _auditLog = new ActionAuditLog(_auditLogPath);
        _consentStore = new ActionConsentStore();

        var settingsPath = Path.Combine(_testStateDir, "sensor-settings.v1.json");
        _settingsStore = new SensorSettingsStore(settingsPath);

        _executor = new ProcessTerminationExecutor(parentProcessId: 99999);
        _handler = new ProcessTerminationActionHandler(_executor, _settingsStore, _consentStore, _auditLog);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testStateDir))
                Directory.Delete(_testStateDir, recursive: true);
        }
        catch { }
    }

    [Theory]
    [InlineData(0, null, null)]
    [InlineData(4, null, null)]
    [InlineData(100, "csrss.exe", @"C:\Windows\System32\csrss.exe")]
    [InlineData(101, "lsass.exe", @"C:\Windows\System32\lsass.exe")]
    [InlineData(102, "services.exe", @"C:\Windows\System32\services.exe")]
    [InlineData(103, "wininit.exe", @"C:\Windows\System32\wininit.exe")]
    [InlineData(104, "winlogon.exe", @"C:\Windows\System32\winlogon.exe")]
    [InlineData(105, "smss.exe", @"C:\Windows\System32\smss.exe")]
    [InlineData(106, "svchost.exe", @"C:\Windows\System32\svchost.exe")]
    [InlineData(107, "dwm.exe", @"C:\Windows\System32\dwm.exe")]
    [InlineData(108, "explorer.exe", @"C:\Windows\explorer.exe")]
    [InlineData(109, "Downpour.Desktop.exe", @"C:\Downpour\Downpour.Desktop.exe")]
    [InlineData(110, "Downpour.Service.exe", @"C:\Downpour\Downpour.Service.exe")]
    [InlineData(111, "Downpour.Scanner.exe", @"C:\Downpour\Downpour.Scanner.exe")]
    [InlineData(112, "Downpour.UpdateHelper.exe", @"C:\Downpour\Downpour.UpdateHelper.exe")]
    [InlineData(99999, "any.exe", @"C:\Temp\any.exe")] // Parent Desktop PID
    public void DenyReason_RejectsCriticalSystemAndProtectedProcesses(int pid, string? processName, string? imagePath)
    {
        var reason = _executor.DenyReason(pid, processName, imagePath);
        Assert.NotNull(reason);
        Assert.NotEmpty(reason);
    }

    [Fact]
    public void DenyReason_RejectsServiceOwnProcess()
    {
        var currentPid = Environment.ProcessId;
        var reason = _executor.DenyReason(currentPid, "Downpour.Service", null);
        Assert.NotNull(reason);
        Assert.Contains("own process", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Inspect_RejectsNonexistentPid()
    {
        int nonExistentPid = 999999;
        var ex = Assert.Throws<ProcessTerminationRejectedException>(() =>
            _executor.Inspect(nonExistentPid, DateTimeOffset.UtcNow));

        Assert.Equal("process-not-found", ex.Code);
    }

    [Fact]
    public void Inspect_RejectsStartTimeMismatch()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c ping -n 10 127.0.0.1 > nul",
            CreateNoWindow = true,
            UseShellExecute = false
        };
        using var target = Process.Start(psi);
        Assert.NotNull(target);
        try
        {
            var fakeStartTime = target.StartTime.ToUniversalTime().AddHours(-5);
            var ex = Assert.Throws<ProcessTerminationRejectedException>(() =>
                _executor.Inspect(target.Id, fakeStartTime));

            Assert.Equal("process-identity-mismatched", ex.Code);
        }
        finally
        {
            if (!target.HasExited)
            {
                try { target.Kill(); } catch { }
            }
        }
    }

    [Fact]
    public async Task HandleAsync_RejectsDeniedCaller()
    {
        var request = new ProcessTerminationRequest(
            1,
            Guid.NewGuid(),
            ProcessTerminationOperations.Preview,
            Environment.ProcessId,
            DateTimeOffset.UtcNow);

        var response = await _handler.HandleAsync(request, callerDenial: "Unauthorized client", CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("denied-caller", response.ResultCode);
        Assert.Contains("Unauthorized", response.Message);

        var recentAudit = _auditLog.ReadRecent(1);
        Assert.Single(recentAudit);
        Assert.Contains("denied-caller", recentAudit[0]);
    }

    [Fact]
    public async Task HandleAsync_RejectsWhenFeatureSwitchIsDisabled()
    {
        _settingsStore.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.ProcessTerminationActions, false));

        var request = new ProcessTerminationRequest(
            1,
            Guid.NewGuid(),
            ProcessTerminationOperations.Preview,
            Environment.ProcessId,
            DateTimeOffset.UtcNow);

        var response = await _handler.HandleAsync(request, callerDenial: null, CancellationToken.None);

        Assert.False(response.Accepted);
        Assert.Equal("disabled", response.ResultCode);
        Assert.False(response.ActionsEnabled);
    }

    [Fact]
    public async Task HandleAsync_PreviewAndTerminate_TerminatesRealProcessWithConsent()
    {
        // 1. Spawn a real harmless background process (ping loop)
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c ping -n 30 127.0.0.1 > nul",
            CreateNoWindow = true,
            UseShellExecute = false
        };
        using var targetProcess = Process.Start(psi);
        Assert.NotNull(targetProcess);
        Assert.False(targetProcess.HasExited);

        try
        {
            var pid = targetProcess.Id;
            var startTime = targetProcess.StartTime.ToUniversalTime();

            // 2. Request Preview
            var previewRequest = new ProcessTerminationRequest(
                1,
                Guid.NewGuid(),
                ProcessTerminationOperations.Preview,
                pid,
                startTime,
                AlertId: "alert-test-123");

            var previewResponse = await _handler.HandleAsync(previewRequest, callerDenial: null, CancellationToken.None);

            Assert.True(previewResponse.Accepted);
            Assert.Equal("preview", previewResponse.ResultCode);
            Assert.NotNull(previewResponse.Preview);
            Assert.Equal(pid, previewResponse.Preview.ProcessId);
            Assert.NotNull(previewResponse.Preview.ConsentToken);
            Assert.NotNull(previewResponse.Preview.ConsentExpiresUtc);
            Assert.NotEmpty(previewResponse.Preview.ExpectedEffects);
            Assert.NotEmpty(previewResponse.Preview.Risks);

            var token = previewResponse.Preview.ConsentToken;

            // 3. Attempt Terminate with invalid token -> fails
            var invalidTokenRequest = new ProcessTerminationRequest(
                1,
                Guid.NewGuid(),
                ProcessTerminationOperations.Terminate,
                pid,
                startTime,
                ConsentToken: "bad-token-value");

            var invalidResponse = await _handler.HandleAsync(invalidTokenRequest, callerDenial: null, CancellationToken.None);
            Assert.False(invalidResponse.Accepted);
            Assert.Equal("denied-consent", invalidResponse.ResultCode);

            // 4. Attempt Terminate with valid token -> succeeds!
            var terminateRequest = new ProcessTerminationRequest(
                1,
                Guid.NewGuid(),
                ProcessTerminationOperations.Terminate,
                pid,
                startTime,
                ConsentToken: token);

            var termResponse = await _handler.HandleAsync(terminateRequest, callerDenial: null, CancellationToken.None);
            Assert.True(termResponse.Accepted);
            Assert.Equal("terminated", termResponse.ResultCode);

            // Verify the process actually exited
            targetProcess.WaitForExit(3000);
            Assert.True(targetProcess.HasExited);

            // 5. Verify audit log recorded both the preview and successful termination
            var audits = _auditLog.ReadRecent(10);
            Assert.Contains(audits, a => a.Contains("preview"));
            Assert.Contains(audits, a => a.Contains("terminated"));
        }
        finally
        {
            if (!targetProcess.HasExited)
            {
                try { targetProcess.Kill(); } catch { }
            }
        }
    }
}
