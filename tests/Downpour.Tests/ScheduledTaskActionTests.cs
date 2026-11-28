using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Xunit;

namespace Downpour.Tests;

public sealed class ScheduledTaskActionTests : IDisposable
{
    private readonly string _dir;
    private readonly SensorSettingsStore _settings;
    private readonly ActionConsentStore _consent = new();
    private readonly InMemoryScheduledTaskBackend _backend = new();
    private readonly ScheduledTaskActionHandler _handler;

    public ScheduledTaskActionTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "downpour_test_taskaction_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _settings = new SensorSettingsStore(Path.Combine(_dir, "sensor-settings.v1.json"));
        var audit = new ActionAuditLog(Path.Combine(_dir, "audit.v1.jsonl"));
        var executor = new ScheduledTaskActionExecutor(_backend);
        _handler = new ScheduledTaskActionHandler(executor, _settings, _consent, audit);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
        }
        catch { }
    }

    [Theory]
    [InlineData(@"\Contoso\Nightly backup", true)]
    [InlineData(@"\Nightly", true)]
    [InlineData(@"Nightly", false)]
    [InlineData(@"\Contoso\", false)]
    [InlineData(@"\Contoso\..\Windows\evil", false)]
    [InlineData("\\Contoso\\bad\nname", false)]
    [InlineData("", false)]
    [InlineData(@"\Contoso\ padded", false)]
    public void PathValidation_RejectsTraversalAndMalformedPaths(string path, bool expected) =>
        Assert.Equal(expected, ScheduledTaskActionExecutor.IsValidTaskPath(path));

    [Theory]
    [InlineData(@"\Microsoft\Windows\Defrag\ScheduledDefrag", true)]
    [InlineData(@"\Downpour\Isolation expiry", true)]
    [InlineData(@"\Microsoft\Windows\WindowsUpdate\AU\Scheduled Start", true)]
    [InlineData(@"\Contoso\Nightly backup", false)]
    [InlineData(@"\Microsoft\WindowsApps\NotAWindowsTask", false)]
    public void ProtectedPaths_CoverWindowsAndDownpourOwnedTasks(string path, bool expected) =>
        Assert.Equal(expected, ScheduledTaskActionExecutor.ProtectedReason(path) is not null);

    [Fact]
    public void PreviewMintsConsentAndEnableExecutesExactlyOnce()
    {
        const string path = @"\Contoso\Nightly backup";
        _backend.Tasks[path] = false;

        var preview = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.PreviewEnable, path), null);

        Assert.True(preview.Accepted, preview.Message);
        Assert.Null(preview.TaskEnabled);
        Assert.True(preview.Preview!.ExpectedEffects.Count > 0);
        var token = preview.Preview.ConsentToken;
        Assert.False(string.IsNullOrWhiteSpace(token));

        var applied = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.Enable, path, token), null);

        Assert.True(applied.Accepted, applied.Message);
        Assert.True(_backend.Tasks[path]);

        var replay = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.Enable, path, token), null);

        Assert.False(replay.Accepted);
        Assert.Equal("denied-consent", replay.ResultCode);
    }

    [Fact]
    public void ProtectedTaskIsRefusedBeforeConsentIsMinted()
    {
        var response = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.PreviewDelete, @"\Microsoft\Windows\Defrag\ScheduledDefrag"), null);

        Assert.False(response.Accepted);
        Assert.Equal("denied-protected-task", response.ResultCode);
        Assert.Null(response.Preview!.ConsentToken);
        Assert.False(_backend.Tasks.ContainsKey(@"\Microsoft\Windows\Defrag\ScheduledDefrag"));
    }

    [Fact]
    public void DeleteRequiresConsentAndRemovesOnlyTheNamedTask()
    {
        const string path = @"\Contoso\Cleanup";
        _backend.Tasks[path] = true;
        _backend.Tasks[@"\Contoso\Keep me"] = true;

        var preview = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.PreviewDelete, path), null);
        var applied = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.Delete, path, preview.Preview!.ConsentToken), null);

        Assert.True(applied.Accepted, applied.Message);
        Assert.False(_backend.Tasks.ContainsKey(path));
        Assert.True(_backend.Tasks[@"\Contoso\Keep me"]);
    }

    [Fact]
    public void DisabledSwitchRefusesPreviewAndExecution()
    {
        _settings.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.ScheduledTaskActions, false));

        var response = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.PreviewDisable, @"\Contoso\Nightly backup"), null);

        Assert.False(response.Accepted);
        Assert.Equal("disabled", response.ResultCode);
        Assert.False(response.ActionsEnabled);
        Assert.Null(response.Preview);
    }

    [Fact]
    public void CallerDenialWinsOverEverythingElse()
    {
        var response = _handler.Handle(new ScheduledTaskActionRequest(1, Guid.NewGuid(),
            ScheduledTaskActionOperations.PreviewDelete, @"\Contoso\Cleanup"), "Caller is not the signed-in desktop.");

        Assert.False(response.Accepted);
        Assert.Equal("denied-caller", response.ResultCode);
    }

    private sealed class InMemoryScheduledTaskBackend : IScheduledTaskBackend
    {
        public Dictionary<string, bool> Tasks { get; } = new(StringComparer.OrdinalIgnoreCase);

        public ScheduledTaskActionOutcome SetEnabled(string taskPath, bool enabled)
        {
            Tasks[taskPath] = enabled;
            return new(true, enabled ? "task-enabled" : "task-disabled", "Applied.");
        }

        public ScheduledTaskActionOutcome Delete(string taskPath)
        {
            Tasks.Remove(taskPath);
            return new(true, "task-deleted", "Removed.");
        }
    }
}
