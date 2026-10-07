using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Downpour.Service;

/// <summary>
/// Authenticode signature verifier for local files.
/// Distinguishes cryptographically valid Microsoft-signed binaries from unsigned,
/// tampered, or third-party binaries using WinVerifyTrust and Windows Catalog services.
/// </summary>
public interface IAuthenticodeVerifier
{
    /// <summary>
    /// Checks whether the specified file is signed by a trusted Microsoft certificate,
    /// either via an embedded Authenticode signature or via the system catalog database.
    /// </summary>
    bool IsMicrosoftSigned(string filePath);
}

/// <summary>
/// Native Windows Authenticode verification using wintrust.dll and CryptCATAdmin.
/// Read-only: never modifies files or system certificate stores.
/// </summary>
public sealed class AuthenticodeVerifier : IAuthenticodeVerifier, IDisposable
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private static readonly HashSet<string> SignedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".ocx", ".cpl", ".efi", ".scr", ".msi", ".cat", ".ax", ".node", ".drv", ".mui"
    };

    private readonly CatalogSignatureVerifier? _catalogVerifier;

    public AuthenticodeVerifier()
    {
        _catalogVerifier = CatalogSignatureVerifier.TryCreate(out _);
    }

    public bool IsMicrosoftSigned(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return false;

        // Fast check: avoid WinVerifyTrust overhead for non-binary / non-PE files
        if (!IsPotentialSignedBinary(filePath))
            return false;

        // 1. Check embedded Authenticode signature via WinVerifyTrust
        if (VerifyEmbeddedSignature(filePath, out var signerName))
        {
            if (IsMicrosoftSignerName(signerName))
                return true;
        }

        // 2. Fallback: check Windows system catalogs (many System32 binaries and drivers are catalog-signed)
        if (_catalogVerifier is not null)
        {
            var catalogResult = _catalogVerifier.Verify(filePath);
            if (catalogResult.IsSigned && IsMicrosoftSignerName(catalogResult.SignerName))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Verifies the embedded Authenticode signature of a file.
    /// Returns true if the signature is cryptographically valid and chains to a trusted root authority.
    /// </summary>
    internal static bool VerifyEmbeddedSignature(string filePath, out string? signerName)
    {
        signerName = null;
        var fileInfo = new WintrustFileInfo
        {
            cbStruct = Marshal.SizeOf<WintrustFileInfo>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var fileInfoBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
        var action = GenericVerifyV2;
        var trustData = new WintrustData();

        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoBuffer, false);
            trustData = new WintrustData
            {
                cbStruct = Marshal.SizeOf<WintrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pUnion = fileInfoBuffer,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdCacheOnlyUrlRetrieval
            };

            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            if (result == 0) // TRUST_E_SUCCESS
            {
                signerName = ReadSigner(trustData.hWVTStateData);
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (trustData.cbStruct != 0)
            {
                trustData.dwStateAction = WtdStateActionClose;
                WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            }
            if (fileInfoBuffer != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WintrustFileInfo>(fileInfoBuffer);
                Marshal.FreeHGlobal(fileInfoBuffer);
            }
        }
    }

    /// <summary>
    /// Checks whether the signer name matches Microsoft production signing authorities.
    /// </summary>
    public static bool IsMicrosoftSignerName(string? signer)
    {
        if (string.IsNullOrWhiteSpace(signer)) return false;
        return signer.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
            || signer.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase)
            || signer.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPotentialSignedBinary(string filePath)
    {
        var ext = Path.GetExtension(filePath);
        if (SignedExtensions.Contains(ext)) return true;

        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length < 2) return false;
            var b1 = stream.ReadByte();
            var b2 = stream.ReadByte();
            return b1 == 'M' && b2 == 'Z'; // PE MZ header
        }
        catch
        {
            return false;
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
        if (!string.IsNullOrWhiteSpace(name) && IsMicrosoftSignerName(name))
            return name;
        if (certificate.Subject.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
            || certificate.Issuer.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase))
        {
            return string.IsNullOrWhiteSpace(name) ? certificate.Subject : $"{name} ({certificate.Subject})";
        }
        return string.IsNullOrWhiteSpace(name) ? certificate.Subject : name;
    }

    public void Dispose()
    {
        _catalogVerifier?.Dispose();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustFileInfo
    {
        public int cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
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
}
