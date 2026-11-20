using System.Security.Cryptography;
using System.Text;

namespace Downpour.Core;

/// <summary>What a user chose to take to another PC. Feed and API keys are refused by default.</summary>
public sealed record PortableBundlePlan(bool IncludeSettings, bool IncludeSuppressions, bool IncludeCases, bool IncludeFeedKeys);

public sealed record PortableBundlePreview(IReadOnlyList<string> Contents, IReadOnlyList<string> Refusals, bool CanExport);

/// <summary>
/// DPAPI binds state to one user on one machine, which is right for secrets and wrong for migration: a new PC inherits
/// nothing. A portable bundle is a separate, explicitly requested artifact encrypted with a passphrase the user holds,
/// not with the machine key, so it can move. Keys are excluded unless asked for twice, because a bundle that leaks feed
/// credentials is worse than re-entering them.
/// </summary>
public static class PortableSettingsBundle
{
    public const int SaltBytes = 16;
    public const int NonceBytes = 12;
    public const int TagBytes = 16;
    public const int Iterations = 210_000;
    public const int MinimumPassphraseLength = 12;
    private static readonly byte[] Magic = "DPNB1"u8.ToArray();

    public static PortableBundlePreview Preview(PortableBundlePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var contents = new List<string>();
        var refusals = new List<string>();
        if (plan.IncludeSettings) contents.Add("Application settings");
        if (plan.IncludeSuppressions) contents.Add("False-positive suppressions and their expiry");
        if (plan.IncludeCases) contents.Add("Selected investigation cases");
        if (plan.IncludeFeedKeys) refusals.Add("Threat feed credentials are excluded: re-enter them on the new PC so the bundle cannot leak them.");
        if (contents.Count == 0) refusals.Add("Nothing was selected, so there is nothing to export.");
        return new PortableBundlePreview(contents, refusals, contents.Count > 0);
    }

    public static byte[] Encrypt(string passphrase, ReadOnlySpan<byte> plaintext)
    {
        ValidatePassphrase(passphrase);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var key = DeriveKey(passphrase, salt);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        using (var aes = new AesGcm(key, TagBytes))
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Magic);
        var blob = new byte[Magic.Length + SaltBytes + NonceBytes + TagBytes + ciphertext.Length];
        var offset = 0;
        Magic.CopyTo(blob, offset); offset += Magic.Length;
        salt.CopyTo(blob, offset); offset += SaltBytes;
        nonce.CopyTo(blob, offset); offset += NonceBytes;
        tag.CopyTo(blob, offset); offset += TagBytes;
        ciphertext.CopyTo(blob, offset);
        return blob;
    }

    public static byte[] Decrypt(string passphrase, ReadOnlySpan<byte> blob)
    {
        ValidatePassphrase(passphrase);
        if (blob.Length < Magic.Length + SaltBytes + NonceBytes + TagBytes) throw new InvalidDataException("The bundle is truncated.");
        if (!blob[..Magic.Length].SequenceEqual(Magic)) throw new InvalidDataException("The bundle is not a Downpour portable bundle.");
        var salt = blob.Slice(Magic.Length, SaltBytes);
        var nonce = blob.Slice(Magic.Length + SaltBytes, NonceBytes);
        var tag = blob.Slice(Magic.Length + SaltBytes + NonceBytes, TagBytes);
        var ciphertext = blob[(Magic.Length + SaltBytes + NonceBytes + TagBytes)..];
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(DeriveKey(passphrase, salt), TagBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Magic);
        }
        catch (CryptographicException) { throw new InvalidDataException("The bundle could not be decrypted: wrong passphrase or changed contents."); }
        return plaintext;
    }

    private static void ValidatePassphrase(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        if (passphrase.Length < MinimumPassphraseLength)
            throw new ArgumentException($"Use a passphrase of at least {MinimumPassphraseLength} characters.", nameof(passphrase));
    }

    private static byte[] DeriveKey(string passphrase, ReadOnlySpan<byte> salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt.ToArray(), Iterations, HashAlgorithmName.SHA256, 32);
}
