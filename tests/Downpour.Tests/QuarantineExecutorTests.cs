using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class QuarantineExecutorTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "DownpourQuarantineTests", Guid.NewGuid().ToString("N"));
    private readonly string _files;
    private readonly QuarantineVault _vault;
    private readonly OperationJournal _journal;
    private readonly QuarantineExecutor _executor;

    public QuarantineExecutorTests()
    {
        _files = Path.Combine(_root, "files");
        Directory.CreateDirectory(_files);
        _vault = new QuarantineVault(Path.Combine(_root, "vault"));
        _journal = new OperationJournal(Path.Combine(_root, "journal", "operations.db"));
        _journal.InitializeAsync().GetAwaiter().GetResult();
        _executor = new QuarantineExecutor(_vault, _journal);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string CreateFile(string name, byte[] content)
    {
        var path = Path.Combine(_files, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    private static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    [Fact]
    public async Task QuarantineThenRestoreRoundTripsContentAndTimestamps()
    {
        var content = RandomNumberGenerator.GetBytes(QuarantineVault.ChunkSize * 3 + 17);
        var path = CreateFile("sample.bin", content);
        var written = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(path, written);

        var candidate = _executor.Inspect(path);
        Assert.Null(candidate.DenyReason);
        Assert.Equal(Sha(content), candidate.Sha256);

        var result = await _executor.QuarantineAsync(path, candidate.Sha256, "test", CancellationToken.None);
        Assert.True(result.Succeeded, result.Message);
        Assert.False(File.Exists(path));
        Assert.Single(_vault.List());

        var restored = await _executor.RestoreAsync(result.ObjectId!, null, CancellationToken.None);
        Assert.True(restored.Succeeded, restored.Message);
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Equal(written, File.GetLastWriteTimeUtc(path));
        Assert.NotNull(_vault.List().Single().RestoredAtUtc);
        Assert.Empty(await Unresolved());
    }

    [Fact]
    public async Task EmptyFileRoundTrips()
    {
        var path = CreateFile("empty.txt", []);
        var result = await _executor.QuarantineAsync(path, Sha([]), "test", CancellationToken.None);
        Assert.True(result.Succeeded, result.Message);
        Assert.True((await _executor.RestoreAsync(result.ObjectId!, null, CancellationToken.None)).Succeeded);
        Assert.Empty(File.ReadAllBytes(path));
    }

    [Fact]
    public async Task VaultNeverStoresPlaintext()
    {
        var marker = Encoding.ASCII.GetBytes("DOWNPOUR-PLAINTEXT-MARKER-" + new string('Z', 200));
        var path = CreateFile("marker.txt", marker);
        var result = await _executor.QuarantineAsync(path, Sha(marker), "test", CancellationToken.None);
        Assert.True(result.Succeeded);
        foreach (var file in Directory.EnumerateFiles(_vault.Root))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.Equal(-1, bytes.AsSpan().IndexOf(marker.AsSpan(0, 26)));
        }
    }

    [Fact]
    public async Task RestoreNeverOverwritesAnExistingFile()
    {
        var path = CreateFile("doc.txt", "original"u8.ToArray());
        var result = await _executor.QuarantineAsync(path, Sha("original"u8.ToArray()), "test", CancellationToken.None);
        File.WriteAllText(path, "new file the user created");

        var restored = await _executor.RestoreAsync(result.ObjectId!, null, CancellationToken.None);
        Assert.False(restored.Succeeded);
        Assert.Equal("target-exists", restored.ResultCode);
        Assert.Equal("new file the user created", File.ReadAllText(path));

        var alternate = Path.Combine(_files, "doc (restored).txt");
        Assert.True((await _executor.RestoreAsync(result.ObjectId!, alternate, CancellationToken.None)).Succeeded);
        Assert.Equal("original", File.ReadAllText(alternate));
        Assert.Equal("already-restored", (await _executor.RestoreAsync(result.ObjectId!, Path.Combine(_files, "x.txt"), CancellationToken.None)).ResultCode);
    }

    [Fact]
    public async Task ChangedFileIsNotQuarantined()
    {
        var path = CreateFile("changing.txt", "reviewed"u8.ToArray());
        var reviewed = _executor.Inspect(path).Sha256;
        File.WriteAllText(path, "changed after review");
        var result = await _executor.QuarantineAsync(path, reviewed, "test", CancellationToken.None);
        Assert.Equal("denied-hash-changed", result.ResultCode);
        Assert.True(File.Exists(path));
        Assert.Empty(_vault.List());
    }

    [Fact]
    public async Task HardLinkedFileIsRejected()
    {
        var path = CreateFile("linked.txt", "data"u8.ToArray());
        Assert.True(CreateHardLinkW(Path.Combine(_files, "linked-2.txt"), path, IntPtr.Zero));
        var result = await _executor.QuarantineAsync(path, Sha("data"u8.ToArray()), "test", CancellationToken.None);
        Assert.Equal("denied-hard-link", result.ResultCode);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task DirectoryAndJunctionTargetsAreRejected()
    {
        var folder = Path.Combine(_files, "folder");
        Directory.CreateDirectory(folder);
        var result = await _executor.QuarantineAsync(folder, new string('0', 64), "test", CancellationToken.None);
        Assert.False(result.Succeeded);
        Assert.True(Directory.Exists(folder));

        var link = Path.Combine(_files, "link.txt");
        try { File.CreateSymbolicLink(link, CreateFile("target.txt", "t"u8.ToArray())); }
        catch (IOException) { return; } // Symbolic links need Developer Mode or elevation.
        catch (UnauthorizedAccessException) { return; }
        var linked = await _executor.QuarantineAsync(link, Sha("t"u8.ToArray()), "test", CancellationToken.None);
        Assert.Equal("denied-reparse-or-directory", linked.ResultCode);
        Assert.True(File.Exists(Path.Combine(_files, "target.txt")));
    }

    [Theory]
    [InlineData("relative\\file.txt")]
    [InlineData("C:\\file.txt:stream")]
    [InlineData("")]
    public async Task InvalidPathsAreRejected(string path)
    {
        var result = await _executor.QuarantineAsync(path, new string('0', 64), "test", CancellationToken.None);
        Assert.Equal("invalid-path", result.ResultCode);
    }

    [Fact]
    public void DenyListProtectsSystemAndSecurityFolders()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        Assert.NotNull(QuarantineExecutor.DenyReason(Path.Combine(windows, "System32", "kernel32.dll")));
        Assert.NotNull(QuarantineExecutor.DenyReason(Path.Combine(programFiles, "Windows Defender", "MsMpEng.exe")));
        Assert.NotNull(QuarantineExecutor.DenyReason(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state", "x.db")));
        Assert.NotNull(QuarantineExecutor.DenyReason(Path.Combine(AppContext.BaseDirectory, "Downpour.Service.dll")));
        Assert.Null(QuarantineExecutor.DenyReason(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "setup.exe")));
        Assert.Null(QuarantineExecutor.DenyReason(Path.Combine(windows + "Old", "file.txt")));
    }

    [Fact]
    public async Task TamperedOrTruncatedVaultIsDetectedAndRestoreFails()
    {
        var content = RandomNumberGenerator.GetBytes(QuarantineVault.ChunkSize + 100);
        var path = CreateFile("tamper.bin", content);
        var result = await _executor.QuarantineAsync(path, Sha(content), "test", CancellationToken.None);
        var stored = _vault.ContentPath(result.ObjectId!);
        var original = File.ReadAllBytes(stored);

        var flipped = (byte[])original.Clone();
        flipped[40] ^= 0xFF;
        File.WriteAllBytes(stored, flipped);
        Assert.ThrowsAny<CryptographicException>(() => _vault.Decrypt(result.ObjectId!, null));
        Assert.False((await _executor.RestoreAsync(result.ObjectId!, null, CancellationToken.None)).Succeeded);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.EnumerateFiles(_files, ".downpour-restore-*"));

        File.WriteAllBytes(stored, original[..^30]);
        Assert.ThrowsAny<CryptographicException>(() => _vault.Decrypt(result.ObjectId!, null));
        File.WriteAllBytes(stored, [.. original, 1, 2, 3]);
        Assert.ThrowsAny<CryptographicException>(() => _vault.Decrypt(result.ObjectId!, null));

        // A valid copy of another object does not authenticate under this object's ID.
        File.WriteAllBytes(stored, original);
        var other = "obj-" + Guid.NewGuid().ToString("N");
        File.Copy(stored, _vault.ContentPath(other));
        Assert.ThrowsAny<CryptographicException>(() => _vault.Decrypt(other, null));
        Assert.Equal(Sha(content), _vault.Decrypt(result.ObjectId!, null));
    }

    [Fact]
    public async Task RecoveryRollsBackWhenOriginalStillExists()
    {
        var content = "still here"u8.ToArray();
        var path = CreateFile("present.txt", content);
        var objectId = await SimulateCrash(path, content, stage: true);
        var notes = await _executor.RecoverAsync(CancellationToken.None);
        Assert.Contains(notes, note => note.Contains("rolled back"));
        Assert.True(File.Exists(path));
        Assert.False(File.Exists(_vault.ContentPath(objectId)));
        Assert.Empty(await Unresolved());
    }

    [Fact]
    public async Task RecoveryCompletesWhenOriginalIsGoneAndCopyVerifies()
    {
        var content = "moved"u8.ToArray();
        var path = CreateFile("gone.txt", content);
        var objectId = await SimulateCrash(path, content, stage: true);
        File.Delete(path);
        var notes = await _executor.RecoverAsync(CancellationToken.None);
        Assert.Contains(notes, note => note.Contains("completed"));
        Assert.Empty(await Unresolved());
        Assert.True((await _executor.RestoreAsync(objectId, null, CancellationToken.None)).Succeeded);
        Assert.Equal(content, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task RecoveryNeverResolvesSilentlyWhenBothCopiesAreMissing()
    {
        var content = "lost"u8.ToArray();
        var path = CreateFile("lost.txt", content);
        var objectId = await SimulateCrash(path, content, stage: true);
        File.Delete(path);
        File.Delete(_vault.ContentPath(objectId));
        var notes = await _executor.RecoverAsync(CancellationToken.None);
        Assert.Contains(notes, note => note.Contains("needs attention"));
        var events = await _journal.GetEventsAsync(Guid.Parse(objectId[4..]));
        Assert.Equal(JournalOperationState.RecoveryRequired, events.Last().State);
    }

    [Fact]
    public async Task RecoveryWithOnlyPreparedStateLeavesOriginalIntact()
    {
        var content = "prepared only"u8.ToArray();
        var path = CreateFile("prepared.txt", content);
        await SimulateCrash(path, content, stage: false);
        await _executor.RecoverAsync(CancellationToken.None);
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Empty(await Unresolved());
    }

    // Failed operations stay listed for review by design; only in-flight states must be resolved by recovery.
    private async Task<IReadOnlyList<JournalOperation>> Unresolved() =>
        (await _journal.GetPendingRecoveryAsync()).Where(operation => operation.State is not JournalOperationState.Failed).ToArray();

    private async Task<string> SimulateCrash(string path, byte[] content, bool stage)
    {
        var operationId = Guid.NewGuid();
        var objectId = "obj-" + operationId.ToString("N");
        await _journal.BeginAsync(operationId, JournalOperationKind.QuarantineFile, QuarantineExecutor.PolicyVersion, objectId, Guid.NewGuid());
        _vault.WriteManifest(new QuarantineManifest(1, objectId, operationId, path, content.Length, Sha(content), 0,
            DateTime.UtcNow, DateTime.UtcNow, null, null, "test", DateTimeOffset.UtcNow));
        if (stage)
        {
            _vault.Encrypt(objectId, content.Length, (offset, buffer) =>
            {
                var count = (int)Math.Min(buffer.Length, content.Length - offset);
                content.AsSpan((int)offset, count).CopyTo(buffer);
                return count;
            });
            await _journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.ContentStaged, "content-staged");
        }
        return objectId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string newLink, string existing, IntPtr security);
}
