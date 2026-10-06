using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Downpour.Contracts;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

/// <summary>
/// Read-only inventory of installed driver packages.
/// Device-bound packages come from the device class driver keys; unbound third-party packages come from
/// %windir%\INF\oem*.inf. Signatures are verified through the system catalog database, because driver
/// INF files are catalog-signed and never carry an embedded signature.
/// </summary>
public sealed class DriverPackageInventoryProvider
{
    internal const int MaximumPackages = 1024;
    private const int MaximumTextLength = 1024;
    private const int MaximumDriverKeys = 8192;
    private const long MaximumInfBytes = 4 * 1024 * 1024;
    private const string ClassRoot = @"SYSTEM\CurrentControlSet\Control\Class";

    public DriverPackageInventorySnapshot Capture()
    {
        var warnings = new List<string>();
        var infDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF");
        var packages = new Dictionary<string, PackageBuilder>(StringComparer.OrdinalIgnoreCase);
        var deniedKeys = 0;

        try
        {
            using var classRoot = Registry.LocalMachine.OpenSubKey(ClassRoot);
            if (classRoot is null)
            {
                warnings.Add("The device class registry key is unavailable.");
            }
            else
            {
                var visited = 0;
                foreach (var classGuid in classRoot.GetSubKeyNames())
                {
                    using var classKey = TryOpen(classRoot, classGuid, ref deniedKeys);
                    if (classKey is null) continue;
                    var className = classKey.GetValue("Class") as string ?? "";
                    foreach (var instance in classKey.GetSubKeyNames())
                    {
                        if (++visited > MaximumDriverKeys) break;
                        if (instance.Length != 4 || !instance.All(char.IsAsciiDigit)) continue;
                        using var driverKey = TryOpen(classKey, instance, ref deniedKeys);
                        if (driverKey?.GetValue("InfPath") is not string infPath || !IsSafeInfName(infPath)) continue;
                        if (!packages.TryGetValue(infPath, out var builder))
                        {
                            if (packages.Count >= MaximumPackages) continue;
                            builder = new PackageBuilder(infPath)
                            {
                                DriverClass = className,
                                ProviderName = driverKey.GetValue("ProviderName") as string ?? "",
                                DriverVersion = driverKey.GetValue("DriverVersion") as string ?? "",
                                Date = driverKey.GetValue("DriverDate") as string ?? "",
                                HardwareId = driverKey.GetValue("MatchingDeviceId") as string ?? ""
                            };
                            packages.Add(infPath, builder);
                        }
                        builder.DeviceCount++;
                    }
                }
                if (visited > MaximumDriverKeys)
                    warnings.Add($"Stopped after {MaximumDriverKeys:N0} driver keys; the inventory is partial.");
            }
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            warnings.Add($"Device class registry could not be read: {ex.GetType().Name}.");
        }

        AddUnboundOemPackages(infDirectory, packages, warnings);

        if (deniedKeys > 0)
            warnings.Add($"{deniedKeys:N0} driver registry keys were not readable and are omitted.");
        if (packages.Count >= MaximumPackages)
            warnings.Add($"Inventory is limited to {MaximumPackages:N0} packages.");

        using var verifier = CatalogSignatureVerifier.TryCreate(out var verifierError);
        if (verifier is null)
            warnings.Add($"Catalog signature verification is unavailable: {verifierError}");

        var entries = packages.Values
            .OrderBy(package => package.InfPath, StringComparer.OrdinalIgnoreCase)
            .Select(package =>
            {
                var fullPath = Path.Combine(infDirectory, package.InfPath);
                var signature = verifier is null
                    ? SignatureResult.Unknown("Verification unavailable")
                    : verifier.Verify(fullPath);
                return new DriverPackageEntry(
                    InfFile: Bound(package.InfPath),
                    OriginalInfFile: Bound(GetDriverStoreOriginalName(fullPath)),
                    DriverClass: Bound(package.DriverClass),
                    ProviderName: Bound(package.ProviderName),
                    DriverVersion: Bound(package.DriverVersion),
                    Date: Bound(package.Date),
                    HardwareId: Bound(package.DeviceCount == 0 ? "(not bound to a device)" : package.HardwareId),
                    IsSigned: signature.IsSigned,
                    SignerName: signature.SignerName is null ? null : Bound(signature.SignerName),
                    SignatureStatus: Bound(signature.Status));
            })
            .ToArray();

        if (entries.Length == 0)
            warnings.Add("No installed driver packages were found.");

        return new DriverPackageInventorySnapshot(1, DateTimeOffset.UtcNow, entries.Length, entries, warnings);
    }

    private static void AddUnboundOemPackages(string infDirectory, Dictionary<string, PackageBuilder> packages, List<string> warnings)
    {
        try
        {
            foreach (var path in Directory.EnumerateFiles(infDirectory, "oem*.inf"))
            {
                var name = Path.GetFileName(path);
                if (!IsSafeInfName(name) || packages.ContainsKey(name)) continue;
                if (packages.Count >= MaximumPackages) break;
                var version = ReadInfVersion(path);
                packages.Add(name, new PackageBuilder(name)
                {
                    DriverClass = version.Class,
                    ProviderName = version.Provider,
                    DriverVersion = version.Version,
                    Date = version.Date
                });
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or SecurityException)
        {
            warnings.Add($"Driver INF directory could not be listed: {ex.GetType().Name}.");
        }
    }

    private static InfVersionInfo ReadInfVersion(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaximumInfBytes) return InfVersionInfo.Empty;
            // Detects UTF-16/UTF-8 byte order marks; Latin-1 is the fallback for ANSI INFs.
            return ParseInfVersion(File.ReadAllText(path, Encoding.Latin1));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or SecurityException)
        {
            return InfVersionInfo.Empty;
        }
    }

    /// <summary>Parses the [Version] section of an INF file, resolving %token% values from [Strings].</summary>
    internal static InfVersionInfo ParseInfVersion(string content)
    {
        var sections = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string>? current = null;
        foreach (var rawLine in content.Split('\n'))
        {
            var line = StripComment(rawLine).Trim();
            if (line.Length == 0) continue;
            if (line[0] == '[' && line.EndsWith(']'))
            {
                var name = line[1..^1].Trim();
                if (!sections.TryGetValue(name, out current))
                {
                    current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    sections.Add(name, current);
                }
                continue;
            }
            var equals = line.IndexOf('=');
            if (current is null || equals <= 0) continue;
            var key = line[..equals].Trim().Trim('"');
            current.TryAdd(key, line[(equals + 1)..].Trim());
        }

        sections.TryGetValue("Version", out var version);
        sections.TryGetValue("Strings", out var strings);
        string Resolve(string key)
        {
            if (version is null || !version.TryGetValue(key, out var value)) return "";
            value = value.Trim().Trim('"');
            if (value.Length > 2 && value[0] == '%' && value[^1] == '%' && strings is not null
                && strings.TryGetValue(value[1..^1], out var resolved))
                value = resolved.Trim().Trim('"');
            return value;
        }

        var driverVer = Resolve("DriverVer");
        var comma = driverVer.IndexOf(',');
        return new InfVersionInfo(
            Resolve("Class"),
            Resolve("Provider"),
            comma >= 0 ? driverVer[(comma + 1)..].Trim() : "",
            comma >= 0 ? driverVer[..comma].Trim() : driverVer);
    }

    private static string StripComment(string line)
    {
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] == '"') inQuotes = !inQuotes;
            else if (line[i] == ';' && !inQuotes) return line[..i];
        }
        return line;
    }

    internal static bool IsSafeInfName(string name) =>
        name.Length is > 4 and <= 128
        && name.EndsWith(".inf", StringComparison.OrdinalIgnoreCase)
        && name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0
        && !name.Contains("..", StringComparison.Ordinal);

    private static RegistryKey? TryOpen(RegistryKey parent, string name, ref int denied)
    {
        try
        {
            return parent.OpenSubKey(name);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            denied++;
            return null;
        }
    }

    private static string GetDriverStoreOriginalName(string infPath)
    {
        var buffer = new StringBuilder(MaximumTextLength);
        return SetupGetInfDriverStoreLocationW(infPath, IntPtr.Zero, null, buffer, buffer.Capacity, out _)
            ? Path.GetFileName(buffer.ToString())
            : "";
    }

    private static string Bound(string value) =>
        value.Length <= MaximumTextLength ? value : value[..MaximumTextLength];

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupGetInfDriverStoreLocationW(
        string fileName, IntPtr alternatePlatformInfo, string? localeName,
        StringBuilder returnBuffer, int returnBufferSize, out int requiredSize);

    private sealed class PackageBuilder(string infPath)
    {
        public string InfPath { get; } = infPath;
        public string DriverClass { get; set; } = "";
        public string ProviderName { get; set; } = "";
        public string DriverVersion { get; set; } = "";
        public string Date { get; set; } = "";
        public string HardwareId { get; set; } = "";
        public int DeviceCount { get; set; }
    }
}

internal sealed record InfVersionInfo(string Class, string Provider, string Version, string Date)
{
    public static InfVersionInfo Empty { get; } = new("", "", "", "");
}

internal sealed record SignatureResult(bool IsSigned, string? SignerName, string Status)
{
    public static SignatureResult Unknown(string reason) => new(false, null, $"Unknown: {reason}");

    /// <summary>Maps a catalog lookup and WinVerifyTrust result to a status. Only a trusted catalog signature counts as signed.</summary>
    internal static SignatureResult Classify(bool catalogFound, uint trustResult, string? signer)
    {
        if (!catalogFound) return new(false, null, "Not signed: no catalog contains this INF");
        return trustResult switch
        {
            0 => new(true, signer, "Valid catalog signature"),
            0x800B0100 => new(false, null, "Not signed: catalog has no signature"),
            0x800B0101 => new(false, signer, "Signature expired"),
            0x800B010C => new(false, signer, "Signer certificate revoked"),
            0x800B0109 => new(false, signer, "Untrusted root certificate"),
            0x80096010 => new(false, signer, "Signature invalid: digest mismatch"),
            0x800B0111 => new(false, signer, "Signer explicitly distrusted"),
            _ => new(false, signer, $"Signature not trusted (0x{trustResult:X8})")
        };
    }
}

/// <summary>
/// Verifies files against the Windows catalog database. Revocation is not fetched over the network;
/// only cached revocation data is used, so a revoked-but-uncached signer can still verify.
/// </summary>
internal sealed class CatalogSignatureVerifier : IDisposable
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private IntPtr _sha256Admin;
    private IntPtr _sha1Admin;

    private CatalogSignatureVerifier(IntPtr sha256Admin, IntPtr sha1Admin)
    {
        _sha256Admin = sha256Admin;
        _sha1Admin = sha1Admin;
    }

    public static CatalogSignatureVerifier? TryCreate(out string? error)
    {
        error = null;
        CryptCATAdminAcquireContext2(out var sha256, IntPtr.Zero, "SHA256", IntPtr.Zero, 0);
        CryptCATAdminAcquireContext(out var sha1, IntPtr.Zero, 0);
        if (sha256 == IntPtr.Zero && sha1 == IntPtr.Zero)
        {
            error = $"CryptCATAdminAcquireContext failed (Win32 {Marshal.GetLastPInvokeError()}).";
            return null;
        }
        return new CatalogSignatureVerifier(sha256, sha1);
    }

    public SignatureResult Verify(string filePath)
    {
        if (!File.Exists(filePath)) return SignatureResult.Unknown("INF file not found");
        try
        {
            using var handle = File.OpenHandle(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            foreach (var (admin, sha256) in new[] { (_sha256Admin, true), (_sha1Admin, false) })
            {
                if (admin == IntPtr.Zero) continue;
                var hash = ComputeHash(admin, handle, sha256);
                if (hash is null) continue;
                var catalog = FindCatalog(admin, hash);
                if (catalog is null) continue;
                return VerifyCatalogMember(admin, catalog, filePath, hash);
            }
            return SignatureResult.Classify(catalogFound: false, 0, null);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return SignatureResult.Unknown($"INF not readable ({ex.GetType().Name})");
        }
    }

    private static byte[]? ComputeHash(IntPtr admin, SafeFileHandle handle, bool sha256)
    {
        // The first call fails with ERROR_INSUFFICIENT_BUFFER and reports the hash size.
        var size = 0;
        _ = sha256
            ? CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0)
            : CryptCATAdminCalcHashFromFileHandle(handle, ref size, null, 0);
        if (size is <= 0 or > 64) return null;
        var hash = new byte[size];
        var ok = sha256
            ? CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)
            : CryptCATAdminCalcHashFromFileHandle(handle, ref size, hash, 0);
        return ok ? hash : null;
    }

    private static string? FindCatalog(IntPtr admin, byte[] hash)
    {
        var previous = IntPtr.Zero;
        var catalogContext = CryptCATAdminEnumCatalogFromHash(admin, hash, hash.Length, 0, ref previous);
        if (catalogContext == IntPtr.Zero) return null;
        try
        {
            var info = new CatalogInfo { cbStruct = Marshal.SizeOf<CatalogInfo>() };
            return CryptCATCatalogInfoFromContext(catalogContext, ref info, 0) ? info.wszCatalogFile : null;
        }
        finally
        {
            CryptCATAdminReleaseCatalogContext(admin, catalogContext, 0);
        }
    }

    private static SignatureResult VerifyCatalogMember(IntPtr admin, string catalogPath, string filePath, byte[] hash)
    {
        var memberTag = Convert.ToHexString(hash);
        var hashBuffer = Marshal.AllocHGlobal(hash.Length);
        var catalogInfoBuffer = IntPtr.Zero;
        var action = GenericVerifyV2;
        var trustData = new WintrustData();
        try
        {
            Marshal.Copy(hash, 0, hashBuffer, hash.Length);
            var catalogInfo = new WintrustCatalogInfo
            {
                cbStruct = Marshal.SizeOf<WintrustCatalogInfo>(),
                pcwszCatalogFilePath = catalogPath,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = filePath,
                pbCalculatedFileHash = hashBuffer,
                cbCalculatedFileHash = hash.Length,
                hCatAdmin = admin
            };
            catalogInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustCatalogInfo>());
            Marshal.StructureToPtr(catalogInfo, catalogInfoBuffer, false);
            trustData = new WintrustData
            {
                cbStruct = Marshal.SizeOf<WintrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceCatalog,
                pUnion = catalogInfoBuffer,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdCacheOnlyUrlRetrieval
            };
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            var signer = ReadSigner(trustData.hWVTStateData);
            return SignatureResult.Classify(catalogFound: true, unchecked((uint)result), signer);
        }
        finally
        {
            if (trustData.cbStruct != 0)
            {
                trustData.dwStateAction = WtdStateActionClose;
                WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            }
            if (catalogInfoBuffer != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WintrustCatalogInfo>(catalogInfoBuffer);
                Marshal.FreeHGlobal(catalogInfoBuffer);
            }
            Marshal.FreeHGlobal(hashBuffer);
        }
    }

    private static string? ReadSigner(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero) return null;
        var providerData = WTHelperProvDataFromStateData(stateData);
        if (providerData == IntPtr.Zero) return null;
        var signer = WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
        if (signer == IntPtr.Zero) return null;
        // CRYPT_PROVIDER_SGNR: DWORD cbStruct; FILETIME sftVerifyAsOf; DWORD csCertChain; CRYPT_PROVIDER_CERT* pasCertChain
        var certCount = Marshal.ReadInt32(signer, 12);
        var chain = Marshal.ReadIntPtr(signer, 16);
        if (certCount <= 0 || chain == IntPtr.Zero) return null;
        // CRYPT_PROVIDER_CERT: DWORD cbStruct; PCCERT_CONTEXT pCert
        var certContext = Marshal.ReadIntPtr(chain, IntPtr.Size);
        if (certContext == IntPtr.Zero) return null;
        using var certificate = new X509Certificate2(certContext);
        var name = certificate.GetNameInfo(X509NameType.SimpleName, false);
        return string.IsNullOrWhiteSpace(name) ? certificate.Subject : name;
    }

    public void Dispose()
    {
        if (_sha256Admin != IntPtr.Zero) CryptCATAdminReleaseContext(_sha256Admin, 0);
        if (_sha1Admin != IntPtr.Zero) CryptCATAdminReleaseContext(_sha1Admin, 0);
        _sha256Admin = IntPtr.Zero;
        _sha1Admin = IntPtr.Zero;
    }

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public int cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustCatalogInfo
    {
        public int cbStruct;
        public int dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public int cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public int cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WintrustData data);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr providerData, int signerIndex, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, int counterSignerIndex);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr admin, IntPtr subsystem, int flags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr admin, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(SafeFileHandle file, ref int hashSize, byte[]? hash, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref int hashSize, byte[]? hash, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, int hashSize, int flags, ref IntPtr previousCatalog);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, int flags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, int flags);
}
