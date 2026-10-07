using System.Text;
using Downpour.Contracts;
using Downpour.Scanner;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class YaraEngineTests
{
    static YaraEngineTests() => Assert.Null(YaraX.EnsureLoaded());

    private static YaraEngine Compile(params (string Name, string? Source)[] files) => YaraEngine.Compile(files);

    [Fact]
    public void PinnedLibraryLoadsAfterHashCheck()
    {
        Assert.Null(YaraX.EnsureLoaded());
        Assert.Equal("1.21.0", YaraX.PinnedVersion);
    }

    [Fact]
    public void LibraryWithWrongHashIsRefused()
    {
        var folder = Path.Combine(Path.GetTempPath(), "DownpourYaraHash", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var fake = Path.Combine(folder, "yara_x_capi.dll");
            File.WriteAllBytes(fake, "not the pinned library"u8.ToArray());
            Assert.Contains("pinned hash", YaraX.VerifyPinned(fake));
            Assert.Contains("not installed", YaraX.VerifyPinned(Path.Combine(folder, "missing.dll")));
            Assert.Null(YaraX.VerifyPinned(Path.Combine(AppContext.BaseDirectory, "yara_x_capi.dll")));
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    [Fact]
    public void MatchReportsRuleNamespaceMetadataAndTags()
    {
        using var engine = Compile(("test.yar", """
            rule evil_marker : malware demo
            {
                meta:
                    severity = "high"
                    description = "Test marker"
                    mitre_attack = "T1059.001"
                strings:
                    $a = "DOWNPOUR-TEST-MARKER"
                condition:
                    $a
            }
            """));
        var (status, _, matches) = engine.Scan(Encoding.ASCII.GetBytes("xx DOWNPOUR-TEST-MARKER yy"));
        Assert.Equal("matched", status);
        var match = Assert.Single(matches);
        Assert.Equal("evil_marker", match.Rule);
        Assert.Equal("test", match.Namespace);
        Assert.Equal("HIGH", match.Severity);
        Assert.Equal("Test marker", match.Description);
        Assert.Equal("T1059.001", match.Technique);
        Assert.Equal(["malware", "demo"], match.Tags);
    }

    [Fact]
    public void CleanAndEmptyInputsDoNotMatch()
    {
        using var engine = Compile(("t.yar", "rule a { strings: $a = \"needle\" condition: $a }"));
        Assert.Equal("clean", engine.Scan(Encoding.ASCII.GetBytes("haystack")).Status);
        Assert.Equal("clean", engine.Scan([]).Status);
    }

    [Fact]
    public void BrokenFileIsReportedAndOthersStillLoad()
    {
        using var engine = Compile(
            ("good.yar", "rule good { condition: true }"),
            ("broken.yar", "rule broken { condition: undefined_identifier }"),
            ("include.yar", "include \"other.yar\"\nrule inc { condition: true }"),
            ("toolarge.yar", null));
        Assert.Equal(1, engine.RuleCount);
        Assert.True(engine.RuleFiles.Single(f => f.File == "good.yar").Loaded);
        Assert.False(engine.RuleFiles.Single(f => f.File == "broken.yar").Loaded);
        Assert.False(string.IsNullOrEmpty(engine.RuleFiles.Single(f => f.File == "broken.yar").Error));
        Assert.False(engine.RuleFiles.Single(f => f.File == "include.yar").Loaded);
        Assert.Contains("1 MiB", engine.RuleFiles.Single(f => f.File == "toolarge.yar").Error);
    }

    [Fact]
    public void SameRuleNameInTwoFilesDoesNotCollide()
    {
        using var engine = Compile(("one.yar", "rule same { condition: true }"), ("two.yar", "rule same { condition: true }"));
        Assert.Equal(2, engine.RuleCount);
        Assert.Equal(2, engine.Scan("x"u8).Matches.Count);
    }

    [Fact]
    public void AllBundledV29RulesLoad()
    {
        using var engine = YaraEngine.LoadDirectory(Path.Combine(AppContext.BaseDirectory, "yara_rules"));
        Assert.Equal(33, engine.RuleFiles.Count);
        Assert.All(engine.RuleFiles, file => Assert.True(file.Loaded, file.File + ": " + file.Error));
        Assert.Equal(179, engine.RuleCount);
    }

    [Theory]
    [InlineData("critical", "CRITICAL")]
    [InlineData(" High ", "HIGH")]
    [InlineData("low", "LOW")]
    [InlineData(null, "MEDIUM")]
    [InlineData("severe", "MEDIUM")]
    public void SeverityIsNormalized(string? input, string expected) => Assert.Equal(expected, YaraEngine.NormalizeSeverity(input));
}

public sealed class YaraScannerHostTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "DownpourYaraHost", Guid.NewGuid().ToString("N"));
    private readonly YaraScannerHost _host = new(NullLogger<YaraScannerHost>.Instance, Path.Combine(AppContext.BaseDirectory, "Downpour.Scanner.exe"));

    public YaraScannerHostTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        _host.Dispose();
        try { Directory.Delete(_folder, true); } catch (IOException) { }
    }

    [Fact]
    public async Task HelperProcessLoadsBundledRulesAndScansFiles()
    {
        var ready = await _host.EnsureStartedAsync(CancellationToken.None);
        Assert.Null(ready.Fatal);
        Assert.Equal(179, ready.RuleCount);

        var note = Path.Combine(_folder, "README_RESTORE.txt");
        File.WriteAllText(note, "ALL YOUR FILES HAVE BEEN ENCRYPTED. Send bitcoin payment to decrypt and restore files.");
        var matched = await _host.ScanAsync(note, CancellationToken.None);
        Assert.Equal("matched", matched.Status);
        Assert.Contains(matched.Matches, match => match.Namespace == "ransomware" && match.Severity == "CRITICAL");

        var clean = Path.Combine(_folder, "notes.txt");
        File.WriteAllText(clean, "shopping list: apples, bread");
        // v29 rules are noisy: benign text can match, but only low-confidence rules, which never raise alerts.
        Assert.All((await _host.ScanAsync(clean, CancellationToken.None)).Matches, match => Assert.True(match.LowConfidence, match.Rule));
        Assert.Equal(108, ready.LowConfidenceRules);

        Assert.Equal("skipped", (await _host.ScanAsync(Path.Combine(_folder, "missing.bin"), CancellationToken.None)).Status);
        Assert.Equal("skipped", (await _host.ScanAsync(note + ":Zone.Identifier", CancellationToken.None)).Status);
        Assert.Equal("ALL YOUR FILES HAVE BEEN ENCRYPTED. Send bitcoin payment to decrypt and restore files.", File.ReadAllText(note));
    }

    [Fact]
    public async Task MissingHelperReportsUnavailableInsteadOfThrowing()
    {
        using var host = new YaraScannerHost(NullLogger<YaraScannerHost>.Instance, Path.Combine(_folder, "nope", "Downpour.Scanner.exe"));
        var ready = await host.EnsureStartedAsync(CancellationToken.None);
        Assert.NotNull(ready.Fatal);
        var result = await host.ScanAsync(Path.Combine(_folder, "x.txt"), CancellationToken.None);
        Assert.Equal("error", result.Status);
    }

    [Fact]
    public async Task HelperKilledMidSessionIsRestartedOnNextFile()
    {
        Assert.Null((await _host.EnsureStartedAsync(CancellationToken.None)).Fatal);
        foreach (var process in System.Diagnostics.Process.GetProcessesByName("Downpour.Scanner"))
            if (process.MainModule?.FileName?.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase) == true) process.Kill();
        var file = Path.Combine(_folder, "after.txt");
        File.WriteAllText(file, "hello");
        var first = await _host.ScanAsync(file, CancellationToken.None);
        var second = first.Status == "error" ? await _host.ScanAsync(file, CancellationToken.None) : first;
        Assert.Equal("clean", second.Status);
    }

    [Fact]
    public async Task CleanWindowsSystemFilesRaiseNoHighConfidenceMatches()
    {
        Assert.Null((await _host.EnsureStartedAsync(CancellationToken.None)).Fatal);
        foreach (var name in new[] { "notepad.exe", "kernel32.dll", "ntdll.dll", "cmd.exe" })
        {
            var result = await _host.ScanAsync(Path.Combine(Environment.SystemDirectory, name), CancellationToken.None);
            Assert.All(result.Matches, match => Assert.True(match.LowConfidence, name + ": " + match.Namespace + ":" + match.Rule));
        }
    }
}

public sealed class YaraScanCoordinatorTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "DownpourYaraScan", Guid.NewGuid().ToString("N"));
    private readonly List<SecurityFindingObservation> _ingested = [];

    public YaraScanCoordinatorTests() => Directory.CreateDirectory(Path.Combine(_folder, "sub"));

    public void Dispose()
    {
        try { Directory.Delete(_folder, true); } catch (IOException) { }
    }

    private YaraScanCoordinator Create(FakeBackend backend, IAuthenticodeVerifier? authenticode = null) => new(backend, (findings, _) =>
    {
        lock (_ingested) _ingested.AddRange(findings);
        return Task.CompletedTask;
    }, NullLogger<YaraScanCoordinator>.Instance, authenticode);

    [Fact]
    public async Task RecursiveScanCountsFilesAndRaisesFindings()
    {
        File.WriteAllText(Path.Combine(_folder, "a.txt"), "clean");
        File.WriteAllText(Path.Combine(_folder, "sub", "evil.txt"), "EVIL");
        File.WriteAllText(Path.Combine(_folder, "sub", "b.txt"), "clean");
        var coordinator = Create(new FakeBackend());
        Assert.True(coordinator.Start(_folder, recursive: true).Started);
        await coordinator.Completion;
        var job = coordinator.Current!;
        Assert.Equal("completed", job.State);
        Assert.Equal(3, job.FilesScanned);
        var finding = Assert.Single(job.Findings);
        Assert.EndsWith("evil.txt", finding.Path);
        var alert = Assert.Single(_ingested);
        Assert.Equal(SecurityFindingCatalog.Yara, alert.Source);
        Assert.Equal("CRITICAL", alert.Severity);
        Assert.Equal("T1486", alert.Technique);
    }

    [Fact]
    public async Task LowConfidenceMatchesAreListedButNotRaised()
    {
        File.WriteAllText(Path.Combine(_folder, "noisy.txt"), "NOISY");
        var coordinator = Create(new FakeBackend());
        coordinator.Start(_folder, recursive: false);
        await coordinator.Completion;
        Assert.Single(coordinator.Current!.Findings);
        Assert.Empty(_ingested);
    }

    [Fact]
    public async Task NonRecursiveScanStaysInTopFolder()
    {
        File.WriteAllText(Path.Combine(_folder, "a.txt"), "clean");
        File.WriteAllText(Path.Combine(_folder, "sub", "evil.txt"), "EVIL");
        var coordinator = Create(new FakeBackend());
        coordinator.Start(_folder, recursive: false);
        await coordinator.Completion;
        Assert.Equal(1, coordinator.Current!.FilesScanned);
        Assert.Empty(_ingested);
    }

    [Fact]
    public async Task SecondScanIsRejectedWhileRunningAndCancelStopsIt()
    {
        for (var i = 0; i < 20; i++) File.WriteAllText(Path.Combine(_folder, $"f{i}.txt"), "clean");
        var backend = new FakeBackend { Delay = TimeSpan.FromMilliseconds(100) };
        var coordinator = Create(backend);
        Assert.True(coordinator.Start(_folder, false).Started);
        Assert.Equal("busy", coordinator.Start(_folder, false).Code);
        await Task.Delay(250);
        Assert.True(coordinator.Cancel());
        await coordinator.Completion;
        Assert.Equal("cancelled", coordinator.Current!.State);
        Assert.True(coordinator.Current.FilesScanned < 20);
    }

    [Fact]
    public async Task EngineUnavailableFailsTheJobVisibly()
    {
        File.WriteAllText(Path.Combine(_folder, "a.txt"), "x");
        var coordinator = Create(new FakeBackend { Fatal = "The YARA-X library does not match the pinned hash." });
        coordinator.Start(_folder, false);
        await coordinator.Completion;
        Assert.Equal("failed", coordinator.Current!.State);
        Assert.Contains("pinned hash", coordinator.Current.Message);
    }

    [Fact]
    public async Task PipeRoundTripCarriesFindingsWithMatchesAndTags()
    {
        File.WriteAllText(Path.Combine(_folder, "evil.txt"), "EVIL");
        var backend = new FakeBackend();
        var coordinator = Create(backend);
        var pipeName = "Downpour.Test.Yara." + Guid.NewGuid().ToString("N");
        using var worker = new YaraScanPipeWorker(coordinator, backend, NullLogger<YaraScanPipeWorker>.Instance, pipeName);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var client = new Downpour.Core.YaraScanClient(pipeName);
            Assert.True((await client.StartAsync(_folder, true))!.Accepted);
            await coordinator.Completion;
            var status = await client.StatusAsync();
            Assert.NotNull(status);
            var finding = Assert.Single(status!.Job!.Findings);
            Assert.Equal(["tag-a", "tag-b"], finding.Matches.Single().Tags);
            Assert.NotNull(await client.StatusAsync()); // the worker is still serving after a deep reply
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task FolderScanSkipsMicrosoftSignedFilesWhenEnabled()
    {
        File.WriteAllText(Path.Combine(_folder, "signed.dll"), "EVIL");
        File.WriteAllText(Path.Combine(_folder, "unsigned.dll"), "EVIL");
        var verifier = new FakeAuthenticodeVerifier(path => Path.GetFileName(path).Equals("signed.dll", StringComparison.OrdinalIgnoreCase));
        var coordinator = Create(new FakeBackend(), verifier);
        Assert.True(coordinator.Start(_folder, recursive: false, skipMicrosoftSigned: true).Started);
        await coordinator.Completion;

        var job = coordinator.Current!;
        Assert.Equal("completed", job.State);
        Assert.Equal(1, job.FilesScanned);
        Assert.Equal(1, job.FilesSkipped);
        var finding = Assert.Single(job.Findings);
        Assert.EndsWith("unsigned.dll", finding.Path);
    }

    [Fact]
    public async Task FolderScanDoesNotSkipMicrosoftSignedFilesWhenDisabled()
    {
        File.WriteAllText(Path.Combine(_folder, "signed.dll"), "EVIL");
        File.WriteAllText(Path.Combine(_folder, "unsigned.dll"), "EVIL");
        var verifier = new FakeAuthenticodeVerifier(path => Path.GetFileName(path).Equals("signed.dll", StringComparison.OrdinalIgnoreCase));
        var coordinator = Create(new FakeBackend(), verifier);
        Assert.True(coordinator.Start(_folder, recursive: false, skipMicrosoftSigned: false).Started);
        await coordinator.Completion;

        var job = coordinator.Current!;
        Assert.Equal("completed", job.State);
        Assert.Equal(2, job.FilesScanned);
        Assert.Equal(0, job.FilesSkipped);
        Assert.Equal(2, job.Findings.Count);
    }

    [Fact]
    public async Task SingleFileScanDoesNotSkipEvenIfMicrosoftSigned()
    {
        var file = Path.Combine(_folder, "signed.dll");
        File.WriteAllText(file, "EVIL");
        var verifier = new FakeAuthenticodeVerifier(_ => true);
        var coordinator = Create(new FakeBackend(), verifier);
        Assert.True(coordinator.Start(file, recursive: false, skipMicrosoftSigned: true).Started);
        await coordinator.Completion;

        var job = coordinator.Current!;
        Assert.Equal("completed", job.State);
        Assert.Equal(1, job.FilesScanned);
        Assert.Equal(0, job.FilesSkipped);
        Assert.Single(job.Findings);
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("C:\\x.txt:ads")]
    [InlineData("\\\\.\\PhysicalDrive0")]
    public void UnsafeRootsAreRejected(string path) => Assert.Equal("invalid-path", Create(new FakeBackend()).Start(path, true).Code);

    [Theory]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"status\"}", true)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"start\",\"path\":\"C:\\\\Users\",\"recursive\":true}", true)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"start\",\"path\":\"C:\\\\Users\",\"recursive\":true,\"skipMicrosoftSigned\":false}", true)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"start\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"start\",\"path\":\"C:\\\\Users\",\"recursive\":\"yes\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"start\",\"path\":\"C:\\\\Users\",\"skipMicrosoftSigned\":\"invalid\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"quarantine\"}", false)]
    [InlineData("{\"schemaVersion\":1,\"requestId\":\"6f9619ff-8b86-d011-b42d-00cf4fc964ff\",\"operation\":\"status\",\"extra\":1}", false)]
    public void PipeParserIsStrict(string json, bool valid) =>
        Assert.Equal(valid, YaraScanPipeWorker.ParseStrictRequest(Encoding.UTF8.GetBytes(json)) is not null);

    private sealed class FakeAuthenticodeVerifier(Func<string, bool> predicate) : IAuthenticodeVerifier
    {
        public bool IsMicrosoftSigned(string filePath) => predicate(filePath);
    }

    private sealed class FakeBackend : IYaraScannerBackend
    {
        public string? Fatal { get; init; }
        public TimeSpan Delay { get; init; }
        public ScannerReady? Ready { get; private set; }

        public Task<ScannerReady> EnsureStartedAsync(CancellationToken token) =>
            Task.FromResult(Ready = new ScannerReady(1, "test", 1, [], Fatal));

        public async Task<ScannerFileResult> ScanAsync(string path, CancellationToken token)
        {
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, token);
            if (File.ReadAllText(path) == "NOISY")
                return new ScannerFileResult(1, "matched", null, 5, [new YaraRuleMatch("noisy", "test", "CRITICAL", "", "", [], LowConfidence: true)]);
            return File.ReadAllText(path) == "EVIL"
                ? new ScannerFileResult(1, "matched", null, 4, [new YaraRuleMatch("evil", "test", "CRITICAL", "Evil", "T1486", ["tag-a", "tag-b"])])
                : new ScannerFileResult(1, "clean", null, 5, []);
        }

        public void Dispose() { }
    }
}

public sealed class AuthenticodeVerifierTests
{
    [Theory]
    [InlineData("Microsoft Windows", true)]
    [InlineData("Microsoft Corporation", true)]
    [InlineData("Microsoft Windows Production PCA 2011", false)] // a CA, never a leaf signer
    [InlineData("Microsoft Windows Publisher", true)]
    [InlineData("Microsoft Windows Hardware Compatibility Publisher", false)] // signs third-party drivers
    [InlineData("Microsoft Windows Third Party Application Component", false)]
    [InlineData("Microsoft Something LLC", false)]
    [InlineData("Microsoft Corporation (CN=Evil Ltd)", false)]
    [InlineData("Google LLC", false)]
    [InlineData("Untrusted Signer", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    public void IsMicrosoftSignerNameClassification(string? signer, bool expected) =>
        Assert.Equal(expected, AuthenticodeVerifier.IsMicrosoftSignerName(signer));

    [Fact]
    public void VerifyEmbeddedSignatureValidatesRealWindowsBinary()
    {
        var dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
        if (!File.Exists(dotnet)) return;

        var valid = AuthenticodeVerifier.VerifyEmbeddedSignature(dotnet, out var signer);
        Assert.True(valid);
        Assert.True(AuthenticodeVerifier.IsMicrosoftSignerName(signer));
    }

    [Fact]
    public void VerifyEmbeddedSignatureRejectsUnsignedFile()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"downpour-unsigned-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(tempFile, [0x4D, 0x5A, 0x90, 0x00]); // MZ stub without signature
        try
        {
            var valid = AuthenticodeVerifier.VerifyEmbeddedSignature(tempFile, out var signer);
            Assert.False(valid);
            Assert.Null(signer);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void IsMicrosoftSignedReturnsTrueForInboxWindowsBinary()
    {
        using var verifier = new AuthenticodeVerifier();
        var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "notepad.exe");
        if (File.Exists(notepad))
        {
            Assert.True(verifier.IsMicrosoftSigned(notepad));
        }

        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (File.Exists(cmd))
        {
            Assert.True(verifier.IsMicrosoftSigned(cmd));
        }
    }

    [Fact]
    public void IsMicrosoftSignedReturnsFalseForUnsignedAndMissingFiles()
    {
        using var verifier = new AuthenticodeVerifier();
        Assert.False(verifier.IsMicrosoftSigned(Path.Combine(Path.GetTempPath(), "non_existent_file.exe")));

        var tempTxt = Path.Combine(Path.GetTempPath(), $"test-{Guid.NewGuid():N}.txt");
        File.WriteAllText(tempTxt, "not an executable");
        try
        {
            Assert.False(verifier.IsMicrosoftSigned(tempTxt));
        }
        finally
        {
            File.Delete(tempTxt);
        }
    }
}
