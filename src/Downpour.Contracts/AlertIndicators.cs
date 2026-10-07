using System.Net;

namespace Downpour.Contracts;

/// <summary>
/// What a finding's indicator is, so the Threats page can offer the matching response (quarantine a file, block an IP).
/// Only sources whose indicator meaning is known are classified; everything else carries no actionable indicator.
/// </summary>
public static class AlertIndicatorKinds
{
    public const string File = "file";
    public const string Ip = "ip";
    public const string Domain = "domain";
    public const string Hash = "hash";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { File, Ip, Domain, Hash };

    public static string? Classify(string source, string? indicator)
    {
        if (string.IsNullOrWhiteSpace(indicator) || indicator.Length > 512 || indicator.Any(char.IsControl)) return null;
        var value = indicator.Trim();
        return source switch
        {
            SecurityFindingCatalog.Yara => System.IO.Path.IsPathFullyQualified(value) && value.IndexOf(':', 2) < 0 ? File : null,
            SecurityFindingCatalog.Dns => LooksLikeDomain(value) ? Domain : null,
            SecurityFindingCatalog.Intel => IPAddress.TryParse(value, out _) ? Ip
                : value.Length is 32 or 40 or 64 && value.All(Uri.IsHexDigit) ? Hash
                : LooksLikeDomain(value) ? Domain : null,
            _ => null,
        };
    }

    private static bool LooksLikeDomain(string value) =>
        value.Length is > 3 and <= 253 && value.Contains('.') && value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-');
}
