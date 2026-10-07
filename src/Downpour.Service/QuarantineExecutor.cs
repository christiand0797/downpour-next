using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

public sealed record QuarantineOutcome(bool Succeeded, string ResultCode, string Message, string? ObjectId = null, QuarantineManifest? Manifest = null);

/// <summary>Facts about a file read through one handle, used for the consent preview.</summary>
public sealed record QuarantineCandidate(string FinalPath, long Size, string Sha256, string? DenyReason);

/// <summary>
/// Write-ahead quarantine and restore (docs/ACTION_BROKER_THREAT_MODEL.md section 3). The original file is opened once by
/// handle without following reparse points, re-validated by its final path, hashed and encrypted from that handle, verified,
/// and only then deleted through the same handle. Every step is journaled; a crash is resolved by <see cref="RecoverAsync"/>.
/// </summary>
public sealed class QuarantineExecutor(QuarantineVault vault, OperationJournal journal)
{
    public const string PolicyVersion = "1.0.0";
    public const long MaximumFileBytes = 256L * 1024 * 1024;
    public const long QuotaBytes = 2L * 1024 * 1024 * 1024;

    public QuarantineCandidate Inspect(string path)
    {
        using var handle = OpenForQuarantine(path, out var finalPath, out var size);
        var deny = DenyReason(finalPath);
        var sha = deny is null ? HashHandle(handle, size) : "";
        return new QuarantineCandidate(finalPath, size, sha, deny);
    }

    public async Task<QuarantineOutcome> QuarantineAsync(string path, string expectedSha256, string reason, CancellationToken token, string? expectedFinalPath = null)
    {
        SafeFileHandle handle;
        string finalPath;
        long size;
        try
        {
            handle = OpenForQuarantine(path, out finalPath, out size);
        }
        catch (QuarantineRejectedException ex)
        {
            return new(false, ex.Code, ex.Message);
        }

        using (handle)
        {
            if (expectedFinalPath is not null && !finalPath.Equals(expectedFinalPath, StringComparison.OrdinalIgnoreCase))
                return new(false, "denied-path-changed", "The file's location changed after it was reviewed. Review it again.");
            if (DenyReason(finalPath) is { } deny) return new(false, "denied-protected-path", deny);
            if (size > MaximumFileBytes) return new(false, "denied-too-large", "Files larger than 256 MiB are not quarantined.");
            if (UsedBytes() + size > QuotaBytes) return new(false, "denied-quota", "The quarantine store has reached its 2 GiB limit.");
            var sha = HashHandle(handle, size);
            if (!sha.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                return new(false, "denied-hash-changed", "The file changed after it was reviewed. Review it again before quarantining.");

            var operationId = Guid.NewGuid();
            var objectId = "obj-" + operationId.ToString("N");
            await journal.BeginAsync(operationId, JournalOperationKind.QuarantineFile, PolicyVersion, objectId, Guid.NewGuid(), token);

            QuarantineManifest manifest;
            try
            {
                var info = new FileInfo(finalPath);
                manifest = new QuarantineManifest(1, objectId, operationId, finalPath, size, sha, (int)info.Attributes,
                    info.CreationTimeUtc, info.LastWriteTimeUtc, ReadSddl(finalPath), ReadZoneIdentifier(finalPath),
                    Bound(reason, 256), DateTimeOffset.UtcNow);
                // Manifest first (write-ahead), then the encrypted content.
                vault.WriteManifest(manifest);
                var stagedHash = vault.Encrypt(objectId, size, (offset, buffer) => RandomAccess.Read(handle, buffer, offset));
                if (!stagedHash.Equals(sha, StringComparison.OrdinalIgnoreCase)) throw new IOException("The file changed while it was being staged.");
                await journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.ContentStaged, "content-staged", token);

                if (!vault.Decrypt(objectId, null).Equals(sha, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("The staged copy did not verify.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
            {
                vault.DeleteStaged(objectId);
                await journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.Failed, "staging-failed-original-intact", token);
                return new(false, "staging-failed", $"Nothing was changed: {ex.Message}");
            }

            if (!DeleteByHandle(handle, out var deleteError))
            {
                vault.DeleteStaged(objectId);
                await journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.Failed, "delete-failed-original-intact", token);
                return new(false, "delete-failed", $"The original could not be removed ({deleteError}); nothing was changed.");
            }
            await journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.Quarantined, "quarantined", token);
            return new(true, "quarantined", $"Quarantined {Path.GetFileName(finalPath)}.", objectId, manifest);
        }
    }

    /// <summary>Restores to the original path, or to <paramref name="alternatePath"/>; never overwrites an existing file.</summary>
    public async Task<QuarantineOutcome> RestoreAsync(string objectId, string? alternatePath, CancellationToken token)
    {
        if (!vault.TryReadManifest(objectId, out var manifest) || manifest is null)
            return new(false, "not-found", "That quarantined item does not exist.");
        if (manifest.RestoredAtUtc is not null) return new(false, "already-restored", "That item was already restored.");
        var target = Path.GetFullPath(alternatePath ?? manifest.OriginalPath);
        if (File.Exists(target) || Directory.Exists(target))
            return new(false, "target-exists", "A file already exists at the restore location. Choose another location.");
        var directory = Path.GetDirectoryName(target);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
            return new(false, "target-folder-missing", "The restore folder does not exist.");

        var operationId = Guid.NewGuid();
        await journal.BeginAsync(operationId, JournalOperationKind.RestoreFile, PolicyVersion, "obj-" + operationId.ToString("N"), Guid.NewGuid(), token);
        var temporary = Path.Combine(directory, $".downpour-restore-{Guid.NewGuid():N}.tmp");
        try
        {
            string hash;
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                hash = vault.Decrypt(objectId, output);
                output.Flush(flushToDisk: true);
            }
            if (!hash.Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("The restored content did not match the recorded hash.");
            await journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.RestorePrepared, "restore-verified", token);
            File.Move(temporary, target, overwrite: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            if (File.Exists(temporary)) File.Delete(temporary);
            await journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.Failed, "restore-failed", token);
            return new(false, "restore-failed", $"The file was not restored: {ex.Message}");
        }

        var warnings = new List<string>();
        try
        {
            File.SetCreationTimeUtc(target, manifest.CreationTimeUtc);
            File.SetLastWriteTimeUtc(target, manifest.LastWriteTimeUtc);
            File.SetAttributes(target, (FileAttributes)manifest.Attributes & ~FileAttributes.ReadOnly);
            if (manifest.ZoneIdentifier is { Length: > 0 and <= 4096 } zone) File.WriteAllText(target + ":Zone.Identifier", zone);
            if (alternatePath is null && manifest.Sddl is { Length: > 0 } sddl)
            {
                var security = new FileSecurity();
                security.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
                new FileInfo(target).SetAccessControl(security);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or SystemException)
        {
            warnings.Add("Some original metadata could not be restored.");
        }
        vault.WriteManifest(manifest with { RestoredAtUtc = DateTimeOffset.UtcNow, RestoredTo = target });
        await journal.TransitionAsync(operationId, Guid.NewGuid(), JournalOperationState.Restored, "restored", token);
        return new(true, "restored", $"Restored to {target}.{(warnings.Count > 0 ? " " + warnings[0] : "")}", objectId, manifest);
    }

    /// <summary>Resolves interrupted quarantine operations (threat model section 3, step 6). Never deletes an original.</summary>
    public async Task<IReadOnlyList<string>> RecoverAsync(CancellationToken token)
    {
        var notes = new List<string>();
        foreach (var operation in await journal.GetPendingRecoveryAsync(1000, token))
        {
            if (operation.Kind == JournalOperationKind.RestoreFile && operation.State is JournalOperationState.Prepared or JournalOperationState.RestorePrepared)
            {
                // An interrupted restore never moved an unverified file into place; the vault copy is unchanged.
                await journal.TransitionAsync(operation.OperationId, Guid.NewGuid(), JournalOperationState.Failed, "restore-interrupted", token);
                notes.Add($"{operation.ObjectId}: an interrupted restore was cancelled; the quarantined copy is unchanged.");
                continue;
            }
            if (operation.State is not (JournalOperationState.Prepared or JournalOperationState.ContentStaged)) continue;
            var objectId = operation.ObjectId;
            var hasManifest = vault.TryReadManifest(objectId, out var manifest) && manifest is not null;
            var stagedValid = false;
            if (hasManifest && File.Exists(vault.ContentPath(objectId)))
            {
                try { stagedValid = vault.Decrypt(objectId, null).Equals(manifest!.Sha256, StringComparison.OrdinalIgnoreCase); }
                catch (Exception ex) when (ex is IOException or CryptographicException) { stagedValid = false; }
            }
            var originalPresent = hasManifest && File.Exists(manifest!.OriginalPath);

            if (stagedValid && !originalPresent)
            {
                if (operation.State == JournalOperationState.Prepared)
                    await journal.TransitionAsync(operation.OperationId, Guid.NewGuid(), JournalOperationState.ContentStaged, "recovered-staged", token);
                await journal.TransitionAsync(operation.OperationId, Guid.NewGuid(), JournalOperationState.Quarantined, "recovered-quarantined", token);
                notes.Add($"{objectId}: completed an interrupted quarantine.");
            }
            else if (originalPresent)
            {
                vault.DeleteStaged(objectId);
                await journal.TransitionAsync(operation.OperationId, Guid.NewGuid(), JournalOperationState.Failed, "rolled-back-original-intact", token);
                notes.Add($"{objectId}: rolled back; the original file is intact.");
            }
            else
            {
                await journal.TransitionAsync(operation.OperationId, Guid.NewGuid(), JournalOperationState.RecoveryRequired, "original-and-copy-missing", token);
                notes.Add($"{objectId}: needs attention; neither the original nor a valid copy was found.");
            }
        }
        return notes;
    }

    /// <summary>Paths that must never be quarantined (threat model section 2). Checked against the handle's final path.</summary>
    public static string? DenyReason(string finalPath)
    {
        var path = finalPath.TrimEnd('\\');
        bool Under(string? root) => !string.IsNullOrEmpty(root) && (path.Equals(root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (Under(windows)) return "Files under the Windows folder are protected.";
        var serviceDirectory = AppContext.BaseDirectory.TrimEnd('\\');
        // The portable layout places the service in <install>\service; protect the whole install then, not an arbitrary parent.
        var installDirectory = Path.GetFileName(serviceDirectory).Equals("service", StringComparison.OrdinalIgnoreCase)
            ? Path.GetDirectoryName(serviceDirectory) : serviceDirectory;
        if (Under(Path.Combine(localAppData, "DownpourNext")) || Under(installDirectory))
            return "Downpour's own files are protected.";
        foreach (var root in new[] { programFiles, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), programData })
            foreach (var vendor in SecurityVendorFolders)
                if (Under(Path.Combine(root, vendor))) return $"Security software files ({vendor}) are protected.";
        if (Path.GetPathRoot(path)?.TrimEnd('\\').Equals(path, StringComparison.OrdinalIgnoreCase) == true) return "Drive roots are protected.";
        return null;
    }

    private static readonly string[] SecurityVendorFolders =
    [
        "Windows Defender", "Microsoft\\Windows Defender", "Windows Defender Advanced Threat Protection", "Malwarebytes", "ESET",
        "Kaspersky Lab", "Bitdefender", "Norton", "NortonLifeLock", "McAfee", "Avast Software", "AVG", "Sophos", "Trend Micro",
        "CrowdStrike", "SentinelOne", "Webroot", "F-Secure", "WithSecure",
    ];

    private long UsedBytes() =>
        Directory.EnumerateFiles(vault.Root, "obj-*.dpq").Sum(file => new FileInfo(file).Length);

    private static string HashHandle(SafeFileHandle handle, long size)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long offset = 0;
        while (offset < size)
        {
            var read = RandomAccess.Read(handle, buffer, offset);
            if (read <= 0) break;
            sha.AppendData(buffer, 0, read);
            offset += read;
        }
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    internal static SafeFileHandle OpenForQuarantine(string path, out string finalPath, out long size)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || path.Length > 32_000 || path.IndexOf(':', 2) >= 0 || path.Contains('\0'))
            throw new QuarantineRejectedException("invalid-path", "A full local file path is required.");
        var handle = CreateFileW(@"\\?\" + Path.GetFullPath(path), GenericRead | Delete, FileShareRead, IntPtr.Zero, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new QuarantineRejectedException(error == 32 ? "file-in-use" : "open-failed",
                error == 32 ? "The file is in use by another program." : $"The file could not be opened ({new Win32Exception(error).Message}).");
        }
        if (!GetFileInformationByHandle(handle, out var info))
        {
            handle.Dispose();
            throw new QuarantineRejectedException("open-failed", "File information could not be read.");
        }
        if ((info.FileAttributes & 0x400) != 0 || (info.FileAttributes & 0x10) != 0)
        {
            handle.Dispose();
            throw new QuarantineRejectedException("denied-reparse-or-directory", "Links, junctions, and folders are not quarantined.");
        }
        if (info.NumberOfLinks > 1)
        {
            handle.Dispose();
            throw new QuarantineRejectedException("denied-hard-link", "Files with more than one hard link are not quarantined.");
        }
        size = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
        var buffer = new char[32_768];
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length)
        {
            handle.Dispose();
            throw new QuarantineRejectedException("open-failed", "The final file path could not be resolved.");
        }
        finalPath = new string(buffer, 0, (int)length);
        if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) finalPath = @"\\" + finalPath[8..];
        else if (finalPath.StartsWith(@"\\?\", StringComparison.Ordinal)) finalPath = finalPath[4..];
        return handle;
    }

    private static bool DeleteByHandle(SafeFileHandle handle, out string error)
    {
        // FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
        var flags = 0x1u | 0x2u;
        if (SetFileInformationByHandle(handle, FileDispositionInfoEx, ref flags, sizeof(uint)))
        {
            error = "";
            return true;
        }
        // Fall back to classic delete-on-close for file systems without POSIX semantics.
        var classic = 1u;
        if (SetFileInformationByHandle(handle, FileDispositionInfo, ref classic, sizeof(uint)))
        {
            error = "";
            return true;
        }
        error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
        return false;
    }

    private static string? ReadSddl(string path)
    {
        try { return new FileInfo(path).GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorSddlForm(AccessControlSections.Access); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException) { return null; }
    }

    private static string? ReadZoneIdentifier(string path)
    {
        try
        {
            var stream = path + ":Zone.Identifier";
            return File.Exists(stream) && new FileInfo(stream).Length <= 4096 ? File.ReadAllText(stream) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException) { return null; }
    }

    private static string Bound(string value, int max) => value.Length <= max ? value : value[..max];

    private const uint GenericRead = 0x80000000, Delete = 0x00010000, FileShareRead = 0x1, OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000, FileFlagSequentialScan = 0x08000000;
    private const int FileDispositionInfo = 4, FileDispositionInfoEx = 21;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation info);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, [Out] char[] path, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref uint info, int size);
}

public sealed class QuarantineRejectedException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
