using System.Security.Cryptography;

namespace Downpour.Core;

public sealed record PackField(string Name, bool Included, string Reason);

/// <summary>
/// Describes exactly what a case pack will and will not contain before it is written. Evidence sharing is the product's
/// differentiating feature, so the export must be inspectable: included fields carry a reason, excluded fields say why,
/// and nothing that is excluded appears in the written bytes.
/// </summary>
public static class CasePackRedaction
{
    private static readonly HashSet<string> AlwaysExcluded = new(StringComparer.OrdinalIgnoreCase)
    {
        "scriptBlockText", "commandLine", "clipboard", "credentials", "documentText", "browserHistory", "apiKey", "authKey",
    };

    public static IReadOnlyList<PackField> Preview(IEnumerable<string> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        return fields
            .Where(field => !string.IsNullOrWhiteSpace(field))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(field => AlwaysExcluded.Contains(field)
                ? new PackField(field, false, "User content or secret material is never exported, even with consent.")
                : new PackField(field, true, "Metadata collected by a sensor; needed to understand the finding."))
            .OrderByDescending(field => field.Included)
            .ThenBy(field => field.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static bool IsExportable(IReadOnlyList<PackField> preview, string field) =>
        preview.Any(candidate => candidate.Included && string.Equals(candidate.Name, field, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Signs and verifies a case pack with the same detached RSA/SHA-256 scheme as releases, so a recipient can prove who
/// produced a pack and that it was not edited in transit. The private key never leaves the exporting machine.
/// </summary>
public static class CasePackSignature
{
    public static string Sign(ReadOnlySpan<byte> pack, RSA key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Convert.ToBase64String(key.SignData(pack, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    public static ReleaseSignatureStatus Verify(ReadOnlySpan<byte> pack, string? signatureBase64, string? publicKeyPem) =>
        ReleaseSignatureVerifier.Verify(pack, signatureBase64, publicKeyPem);

    public static string Describe(ReleaseSignatureStatus status) => status switch
    {
        ReleaseSignatureStatus.Valid => "The case pack matches the signer's public key.",
        ReleaseSignatureStatus.Unsigned => "Unsigned case pack. Origin cannot be proven; treat the contents as unverified.",
        _ => "The case pack signature does not verify. Do not rely on this evidence.",
    };
}
