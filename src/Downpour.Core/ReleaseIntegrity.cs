using System.Security.Cryptography;

namespace Downpour.Core;

public enum ReleaseSignatureStatus { Unsigned, Valid, Invalid }

/// <summary>
/// Verifies a detached RSA/SHA-256 (PKCS#1 v1.5) signature over the release manifest bytes with a pinned public key.
/// Unsigned releases stay representable so existing packages keep working, but a caller that requires provenance must
/// treat <see cref="ReleaseSignatureStatus.Unsigned"/> as untrusted. The key is supplied by the caller, never fetched,
/// so a compromised download host cannot substitute its own signing key.
/// </summary>
public static class ReleaseSignatureVerifier
{
    public static ReleaseSignatureStatus Verify(ReadOnlySpan<byte> manifest, string? signatureBase64, string? publicKeyPem)
    {
        if (string.IsNullOrWhiteSpace(signatureBase64)) return ReleaseSignatureStatus.Unsigned;
        if (string.IsNullOrWhiteSpace(publicKeyPem)) return ReleaseSignatureStatus.Invalid;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            var signature = Convert.FromBase64String(signatureBase64.Trim());
            return rsa.VerifyData(manifest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                ? ReleaseSignatureStatus.Valid
                : ReleaseSignatureStatus.Invalid;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return ReleaseSignatureStatus.Invalid;
        }
    }
}

public sealed record IntegrityViolation(string RelativePath, string Problem);

/// <summary>
/// Compares installed files with the SHA-256 map in a release manifest. Only files listed in the manifest are checked;
/// extra files are ignored because user data and caches legitimately live beside the program. Paths are constrained to
/// the installation root so a hostile manifest cannot probe elsewhere on disk.
/// </summary>
public static class InstallationIntegrity
{
    public static IReadOnlyList<IntegrityViolation> Verify(string root, IReadOnlyDictionary<string, string> expectedSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentNullException.ThrowIfNull(expectedSha256);
        var fullRoot = Path.GetFullPath(root);
        var prefix = fullRoot.EndsWith(Path.DirectorySeparatorChar) ? fullRoot : fullRoot + Path.DirectorySeparatorChar;
        var violations = new List<IntegrityViolation>();
        foreach (var (relative, expected) in expectedSha256)
        {
            if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains(':') ||
                relative.Split('/', '\\').Contains(".."))
            {
                violations.Add(new(relative, "The manifest path is unsafe."));
                continue;
            }
            var full = Path.GetFullPath(Path.Combine(fullRoot, relative));
            if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add(new(relative, "The manifest path is outside the installation root."));
                continue;
            }
            if (!File.Exists(full))
            {
                violations.Add(new(relative, "The file is missing."));
                continue;
            }
            using var stream = File.OpenRead(full);
            var actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            if (!string.Equals(actual, expected.Trim().ToLowerInvariant(), StringComparison.Ordinal))
                violations.Add(new(relative, "The SHA-256 does not match the manifest."));
        }
        return violations;
    }
}
