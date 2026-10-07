using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class QuarantineActionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "DownpourQuarantineActionTests", Guid.NewGuid().ToString("N"));
    private readonly string _files;
    private readonly QuarantineVault _vault;
    private readonly OperationJournal _journal;
    private readonly QuarantineExecutor _executor;
    private readonly SensorSettingsStore _settings;
    private readonly ActionAuditLog _audit;
    private readonly ManualTime _time = new();
    private readonly QuarantineActionHandler _handler;

    public QuarantineActionTests()
    {
        _files = Path.Combine(_root, "files");
        Directory.CreateDirectory(_files);
        _vault = new QuarantineVault(Path.Combine(_root, "vault"));
        _journal = new OperationJournal(Path.Combine(_root, "journal", "operations.db"));
        _journal.InitializeAsync().GetAwaiter().GetResult();
        _executor = new QuarantineExecutor(_vault, _journal);
        _settings = new SensorSettingsStore(Path.Combine(_root, "settings.json"));
        _audit = new ActionAuditLog(Path.Combine(_root, "audit.jsonl"));
        _handler = new QuarantineActionHandler(_executor, _vault, _settings, new ActionConsentStore(_time), _audit);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string CreateFile(string name, string text)
    {
        var path = Path.Combine(_files, name);
        File.WriteAllText(path, text);
        return path;
    }

    private Task<QuarantineResponse> Send(string operation, string? path = null, string? objectId = null, string? restorePath = null, string? consent = null, string? callerDenial = null) =>
        _handler.HandleAsync(new QuarantineRequest(1, Guid.NewGuid(), operation, path, objectId, restorePath, consent), callerDenial, CancellationToken.None);

    [Fact]
    public async Task PreviewConfirmQuarantineAndRestoreSucceed()
    {
        var path = CreateFile("suspect.exe", "MZ fake");
        var preview = await Send(QuarantineOperations.PreviewQuarantine, path);
        Assert.True(preview.Accepted, preview.Message);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("MZ fake"))).ToLowerInvariant(), preview.Preview!.Sha256);

        var done = await Send(QuarantineOperations.Quarantine, preview.Preview.TargetPath, consent: preview.Preview.ConsentToken);
        Assert.True(done.Accepted, done.Message);
        Assert.False(File.Exists(path));

        var list = await Send(QuarantineOperations.List);
        var item = Assert.Single(list.Items!);
        Assert.Equal("suspect.exe", item.FileName);

        var restorePreview = await Send(QuarantineOperations.PreviewRestore, objectId: item.ObjectId);
        Assert.True(restorePreview.Accepted, restorePreview.Message);
        var restored = await Send(QuarantineOperations.Restore, objectId: item.ObjectId, consent: restorePreview.Preview!.ConsentToken);
        Assert.True(restored.Accepted, restored.Message);
        Assert.Equal("MZ fake", File.ReadAllText(path));

        var audit = _audit.ReadRecent(20);
        Assert.Contains(audit, line => line.Contains("\"quarantined\""));
        Assert.Contains(audit, line => line.Contains("\"restored\""));
    }

    [Fact]
    public async Task ActionWithoutConsentIsDeniedAndAudited()
    {
        var path = CreateFile("a.txt", "a");
        var response = await Send(QuarantineOperations.Quarantine, path, consent: new string('a', 64));
        Assert.Equal("denied-consent", response.ResultCode);
        Assert.True(File.Exists(path));
        Assert.Contains(_audit.ReadRecent(5), line => line.Contains("denied-consent"));
    }

    [Fact]
    public async Task ConsentIsSingleUseAndBoundToTheReviewedFile()
    {
        var first = CreateFile("first.txt", "1");
        var second = CreateFile("second.txt", "2");
        var preview = await Send(QuarantineOperations.PreviewQuarantine, first);
        Assert.Equal("denied-consent", (await Send(QuarantineOperations.Quarantine, second, consent: preview.Preview!.ConsentToken)).ResultCode);
        // The mismatched attempt consumed the token.
        Assert.Equal("denied-consent", (await Send(QuarantineOperations.Quarantine, preview.Preview.TargetPath, consent: preview.Preview.ConsentToken)).ResultCode);
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));
    }

    [Fact]
    public async Task ExpiredConsentIsDenied()
    {
        var path = CreateFile("late.txt", "late");
        var preview = await Send(QuarantineOperations.PreviewQuarantine, path);
        _time.Advance(ActionConsentStore.Lifetime + TimeSpan.FromSeconds(1));
        Assert.Equal("denied-consent", (await Send(QuarantineOperations.Quarantine, preview.Preview!.TargetPath, consent: preview.Preview.ConsentToken)).ResultCode);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task FileChangedAfterPreviewIsNotQuarantined()
    {
        var path = CreateFile("edit.txt", "before");
        var preview = await Send(QuarantineOperations.PreviewQuarantine, path);
        File.WriteAllText(path, "after");
        Assert.Equal("denied-hash-changed", (await Send(QuarantineOperations.Quarantine, preview.Preview!.TargetPath, consent: preview.Preview.ConsentToken)).ResultCode);
        Assert.Equal("after", File.ReadAllText(path));
    }

    [Fact]
    public async Task UnverifiedCallerIsDeniedForEveryOperation()
    {
        var path = CreateFile("b.txt", "b");
        foreach (var operation in QuarantineOperations.All)
        {
            var response = await Send(operation, path, callerDenial: "not the desktop");
            Assert.False(response.Accepted);
            Assert.Equal("denied-caller", response.ResultCode);
        }
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task SwitchOffBlocksActionsButStillLists()
    {
        _settings.Apply(new SensorSettingRequest(1, Guid.NewGuid(), SensorSettingKeys.QuarantineActions, false));
        var path = CreateFile("c.txt", "c");
        var preview = await Send(QuarantineOperations.PreviewQuarantine, path);
        Assert.Equal("disabled", preview.ResultCode);
        Assert.False(preview.ActionsEnabled);
        Assert.True((await Send(QuarantineOperations.List)).Accepted);
    }

    [Fact]
    public async Task ProtectedPathPreviewIssuesNoConsent()
    {
        var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(system)) return;
        var preview = await Send(QuarantineOperations.PreviewQuarantine, system);
        Assert.False(preview.Accepted);
        Assert.Null(preview.Preview?.ConsentToken);
    }

    [Fact]
    public async Task RestorePreviewRefusesExistingTargetAndBadObjectIds()
    {
        var path = CreateFile("d.txt", "d");
        var preview = await Send(QuarantineOperations.PreviewQuarantine, path);
        var done = await Send(QuarantineOperations.Quarantine, preview.Preview!.TargetPath, consent: preview.Preview.ConsentToken);
        File.WriteAllText(path, "replacement");
        var objectId = Assert.Single((await Send(QuarantineOperations.List)).Items!).ObjectId;
        var restore = await Send(QuarantineOperations.PreviewRestore, objectId: objectId);
        Assert.Equal("denied-target", restore.ResultCode);
        Assert.Null(restore.Preview!.ConsentToken);
        Assert.Equal("invalid-request", (await Send(QuarantineOperations.PreviewRestore, objectId: "..\\..\\x")).ResultCode);
        Assert.Equal("invalid-request", (await Send(QuarantineOperations.PreviewRestore, objectId: "obj-" + new string('0', 32))).ResultCode);
        Assert.True(done.Accepted);
    }

    [Theory]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"list\"}", true)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"delete\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"list\",\"command\":\"x\"}", false)]
    [InlineData("{\"schemaVersion\":2,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"list\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"list\",\"operation\":\"restore\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"previewQuarantine\",\"path\":\"relative.txt\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"previewQuarantine\",\"path\":\"C:\\\\a.txt:ads\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"previewQuarantine\",\"path\":\"\\\\\\\\?\\\\C:\\\\a.txt\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"previewQuarantine\",\"path\":5}", false)]
    [InlineData("[]", false)]
    public void StrictParserAcceptsOnlyKnownShapes(string json, bool valid)
    {
        Assert.Equal(valid, QuarantineActionPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(json)) is not null);
    }

    [Fact]
    public async Task PipeRoundTripUsesVerifierAndClient()
    {
        var pipeName = "Downpour.Test.Quarantine." + Guid.NewGuid().ToString("N");
        var verifier = new FakeVerifier();
        using var worker = new QuarantineActionPipeWorker(_handler, _executor, _journal, verifier, NullLogger<QuarantineActionPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var client = new QuarantineClient(pipeName);
            var path = CreateFile("pipe.txt", "pipe");
            var preview = await client.PreviewQuarantineAsync(path);
            Assert.NotNull(preview);
            Assert.True(preview!.Accepted, preview.Message);
            var done = await client.QuarantineAsync(preview.Preview!.TargetPath, preview.Preview.ConsentToken!);
            Assert.True(done!.Accepted, done.Message);
            Assert.False(File.Exists(path));

            verifier.Denial = "wrong caller";
            var denied = await client.ListAsync();
            Assert.Equal("denied-caller", denied!.ResultCode);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    private sealed class FakeVerifier : IActionCallerVerifier
    {
        public string? Denial { get; set; }
        public string? Verify(NamedPipeServerStream pipe) => Denial;
    }

    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
